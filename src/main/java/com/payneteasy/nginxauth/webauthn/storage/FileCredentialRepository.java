package com.payneteasy.nginxauth.webauthn.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * {@code <dir>/<uid>.json} per user. One process owns the directory; the in-memory cache is the
 * authoritative state and every write goes temp → fsync → rename → fsync(dir).
 */
public final class FileCredentialRepository implements IWebAuthnCredentialRepository {

    private static final Logger LOG = LoggerFactory.getLogger(FileCredentialRepository.class);

    private static final Pattern UID       = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._@-]{0,127}");
    private static final String  SUFFIX    = ".json";
    private static final String  TEMP_SUFFIX = ".tmp";
    private static final int     MAX_FILE_BYTES = 1024 * 1024;

    private static final Set<PosixFilePermission> GROUP_OTHER = Set.of(
            PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE, PosixFilePermission.GROUP_EXECUTE,
            PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE, PosixFilePermission.OTHERS_EXECUTE);

    private final Path      directory;
    private final FileOps   fileOps;
    private final UserLocks locks;
    private final SecureRandom random = new SecureRandom();

    private final ConcurrentHashMap<String, UserRecord> cache = new ConcurrentHashMap<>();
    private final Object                indexLock         = new Object();
    private final Map<String, String>   credentialOwners  = new HashMap<>();
    private final Map<String, String>   userHandleOwners  = new HashMap<>();
    private final Map<String, String>   uidsByLowerCase   = new HashMap<>();

    private volatile boolean failed;

    private FileCredentialRepository(Path aDirectory, FileOps aFileOps, UserLocks aLocks) {
        directory = aDirectory;
        fileOps   = aFileOps;
        locks     = aLocks;
    }

    public static boolean isValidUid(String aUid) {
        return aUid != null && UID.matcher(aUid).matches();
    }

    public static FileCredentialRepository open(Path aDirectory, UserLocks aLocks) throws StorageException {
        return open(aDirectory, new DefaultFileOps(), aLocks);
    }

    public static FileCredentialRepository open(Path aDirectory, FileOps aFileOps, UserLocks aLocks) throws StorageException {
        FileCredentialRepository repository = new FileCredentialRepository(aDirectory.toAbsolutePath().normalize(), aFileOps, aLocks);
        repository.load();
        return repository;
    }

    @Override
    public UserLocks locks() {
        return locks;
    }

    @Override
    public Optional<UserRecord> find(String aUid) {
        if (aUid == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(cache.get(aUid));
    }

    @Override
    public Optional<String> ownerOfCredential(String aCredentialId) {
        synchronized (indexLock) {
            String owner = credentialOwners.get(aCredentialId);
            if (owner == null) {
                return Optional.empty();
            }
            // a reservation without a saved record is not an owner yet
            UserRecord record = cache.get(owner);
            if (record == null || record.find(aCredentialId).isEmpty()) {
                return Optional.empty();
            }
            return Optional.of(owner);
        }
    }

    @Override
    public Optional<String> uidForUserHandle(String aUserHandle) {
        synchronized (indexLock) {
            String owner = userHandleOwners.get(aUserHandle);
            if (owner == null || !cache.containsKey(owner)) {
                return Optional.empty();
            }
            return Optional.of(owner);
        }
    }

    @Override
    public boolean isFailed() {
        return failed;
    }

    @Override
    public void save(UserRecord aRecord) throws StorageException {
        String uid = aRecord.uid();
        if (!isValidUid(uid)) {
            throw new StorageException("Invalid uid");
        }
        if (!locks.isHeldByCurrentThread(uid)) {
            throw new IllegalStateException("lock(uid) is not held");
        }
        if (failed) {
            throw new StorageException("Credential storage is in failed state");
        }
        checkRecord(aRecord);

        UserRecord old = cache.get(uid);
        Set<String> oldIds = old == null ? Set.of() : credentialIds(old);
        Set<String> newIds = credentialIds(aRecord);
        Set<String> added = new HashSet<>(newIds);
        added.removeAll(oldIds);
        Set<String> removed = new HashSet<>(oldIds);
        removed.removeAll(newIds);

        reserve(uid, aRecord.userHandle(), added);

        Path target = fileFor(uid);
        Path temp = directory.resolve("." + uid + "." + Long.toHexString(random.nextLong()) + SUFFIX + TEMP_SUFFIX);
        try {
            fileOps.writeAndSync(temp, UserRecordCodec.encode(aRecord));
        } catch (IOException e) {
            deleteQuietly(temp);
            unreserve(uid, aRecord.userHandle(), added, old);
            throw new StorageException("Can't write credential file", e);
        }

        try {
            fileOps.atomicMove(temp, target);
        } catch (IOException e) {
            deleteQuietly(temp);
            reconcile(uid);
            throw new StorageException("Can't rename credential file", e);
        }

        cache.put(uid, aRecord);
        synchronized (indexLock) {
            for (String id : removed) {
                credentialOwners.remove(id, uid);
            }
            if (old != null && !old.userHandle().equals(aRecord.userHandle())) {
                userHandleOwners.remove(old.userHandle(), uid);
            }
        }

        try {
            fileOps.syncDirectory(directory);
        } catch (IOException e) {
            // the rename is visible: disk and cache agree, only durability of the rename is unknown
            LOG.error("Can't fsync credential directory after writing {}", target.getFileName(), e);
        }
    }

    private void reserve(String aUid, String aUserHandle, Set<String> aAdded) throws DuplicateCredentialException {
        synchronized (indexLock) {
            String lower = aUid.toLowerCase(Locale.ROOT);
            String sameName = uidsByLowerCase.get(lower);
            if (sameName != null && !sameName.equals(aUid)) {
                throw new DuplicateCredentialException("uid differs only in case from an existing user");
            }
            String handleOwner = userHandleOwners.get(aUserHandle);
            if (handleOwner != null && !handleOwner.equals(aUid)) {
                throw new DuplicateCredentialException("user handle belongs to another user");
            }
            for (String id : aAdded) {
                String owner = credentialOwners.get(id);
                if (owner != null && !owner.equals(aUid)) {
                    throw new DuplicateCredentialException("credential ID belongs to another user");
                }
                if (owner != null) {
                    // reserved by a concurrent write of the same user; cannot happen under lock(uid)
                    throw new DuplicateCredentialException("credential ID is already reserved");
                }
            }
            for (String id : aAdded) {
                credentialOwners.put(id, aUid);
            }
            userHandleOwners.put(aUserHandle, aUid);
            uidsByLowerCase.put(lower, aUid);
        }
    }

    private void unreserve(String aUid, String aUserHandle, Set<String> aAdded, UserRecord aOld) {
        synchronized (indexLock) {
            for (String id : aAdded) {
                credentialOwners.remove(id, aUid);
            }
            if (aOld == null || !aOld.userHandle().equals(aUserHandle)) {
                userHandleOwners.remove(aUserHandle, aUid);
            }
            if (aOld == null) {
                uidsByLowerCase.remove(aUid.toLowerCase(Locale.ROOT), aUid);
            }
        }
    }

    /**
     * After a failed rename the file may hold either the old or the new record. Re-read it and make the
     * cache and index follow the disk; if that is impossible, stop accepting changes.
     */
    private void reconcile(String aUid) {
        Path file = fileFor(aUid);
        try {
            UserRecord onDisk = Files.exists(file, LinkOption.NOFOLLOW_LINKS) ? readFile(file, aUid) : null;
            synchronized (indexLock) {
                credentialOwners.values().removeIf(aUid::equals);
                userHandleOwners.values().removeIf(aUid::equals);
                if (onDisk == null) {
                    cache.remove(aUid);
                    uidsByLowerCase.remove(aUid.toLowerCase(Locale.ROOT), aUid);
                    return;
                }
                for (StoredCredential credential : onDisk.credentials()) {
                    String owner = credentialOwners.putIfAbsent(credential.credentialId(), aUid);
                    if (owner != null && !owner.equals(aUid)) {
                        throw new IllegalStateException("duplicate credential ID after reconcile");
                    }
                }
                userHandleOwners.put(onDisk.userHandle(), aUid);
                cache.put(aUid, onDisk);
            }
        } catch (Exception e) {
            failed = true;
            LOG.error("Credential storage is inconsistent for one user; refusing further changes until restart", e);
        }
    }

    private void load() throws StorageException {
        try {
            prepareDirectory();
            try (DirectoryStream<Path> entries = Files.newDirectoryStream(directory)) {
                for (Path entry : entries) {
                    loadEntry(entry);
                }
            }
        } catch (IOException e) {
            throw new StorageException("Can't read credential directory " + directory, e);
        }
        LOG.info("Loaded WebAuthn credentials of {} users from {}", cache.size(), directory);
    }

    private void prepareDirectory() throws IOException, StorageException {
        if (!Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
            if (DefaultFileOps.POSIX) {
                Files.createDirectories(directory, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            } else {
                Files.createDirectories(directory);
            }
        }
        BasicFileAttributes attributes = Files.readAttributes(directory, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (attributes.isSymbolicLink() || !attributes.isDirectory()) {
            throw new StorageException("WEBAUTHN_STORAGE_DIR must be a directory, not a symlink: " + directory);
        }
        checkPermissions(directory, "directory");
    }

    private void loadEntry(Path aEntry) throws IOException, StorageException {
        String name = aEntry.getFileName().toString();
        BasicFileAttributes attributes = Files.readAttributes(aEntry, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (attributes.isSymbolicLink()) {
            throw new StorageException("Symlink in credential directory: " + name);
        }
        if (!attributes.isRegularFile()) {
            throw new StorageException("Unexpected entry in credential directory: " + name);
        }
        if (name.startsWith(".") && name.endsWith(SUFFIX + TEMP_SUFFIX)) {
            LOG.warn("Removing leftover temp file {}", name);
            Files.delete(aEntry);
            return;
        }
        if (!name.endsWith(SUFFIX)) {
            throw new StorageException("Unexpected file in credential directory: " + name);
        }
        String uid = name.substring(0, name.length() - SUFFIX.length());
        if (!isValidUid(uid)) {
            throw new StorageException("Invalid uid in file name: " + name);
        }
        checkPermissions(aEntry, "file");

        UserRecord record;
        try {
            record = readFile(aEntry, uid);
        } catch (IllegalArgumentException e) {
            throw new StorageException("Malformed credential file " + name + ": " + e.getMessage());
        }

        synchronized (indexLock) {
            String lower = uid.toLowerCase(Locale.ROOT);
            if (uidsByLowerCase.containsKey(lower)) {
                throw new StorageException("Two credential files differ only in case: " + name);
            }
            if (userHandleOwners.containsKey(record.userHandle())) {
                throw new StorageException("Duplicate user handle in " + name);
            }
            for (StoredCredential credential : record.credentials()) {
                if (credentialOwners.containsKey(credential.credentialId())) {
                    throw new StorageException("Duplicate credential ID in " + name);
                }
                credentialOwners.put(credential.credentialId(), uid);
            }
            userHandleOwners.put(record.userHandle(), uid);
            uidsByLowerCase.put(lower, uid);
        }
        cache.put(uid, record);
    }

    private UserRecord readFile(Path aFile, String aUid) throws IOException {
        byte[] bytes;
        try (InputStream in = Files.newInputStream(aFile, LinkOption.NOFOLLOW_LINKS)) {
            bytes = in.readNBytes(MAX_FILE_BYTES + 1);
        }
        if (bytes.length > MAX_FILE_BYTES) {
            throw new IllegalArgumentException("file is too large");
        }
        UserRecord record = UserRecordCodec.decode(bytes);
        if (!aUid.equals(record.uid())) {
            throw new IllegalArgumentException("uid does not match file name");
        }
        checkRecord(record);
        return record;
    }

    private static void checkRecord(UserRecord aRecord) {
        Set<String> ids = new HashSet<>();
        for (StoredCredential credential : aRecord.credentials()) {
            if (!ids.add(credential.credentialId())) {
                throw new IllegalArgumentException("duplicate credential ID within one user");
            }
            if (!credential.backupEligible() && credential.backupState()) {
                throw new IllegalArgumentException("credential with BE=0 and BS=1");
            }
        }
    }

    private static void checkPermissions(Path aPath, String aKind) throws IOException, StorageException {
        if (!DefaultFileOps.POSIX) {
            return;
        }
        Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(aPath, LinkOption.NOFOLLOW_LINKS);
        for (PosixFilePermission permission : permissions) {
            if (GROUP_OTHER.contains(permission)) {
                throw new StorageException("Credential " + aKind + " " + aPath.getFileName() + " must not be accessible by group/others (expected "
                        + ("directory".equals(aKind) ? "0700" : "0600") + ")");
            }
        }
    }

    private static Set<String> credentialIds(UserRecord aRecord) {
        Set<String> ids = new HashSet<>();
        for (StoredCredential credential : aRecord.credentials()) {
            ids.add(credential.credentialId());
        }
        return ids;
    }

    private Path fileFor(String aUid) {
        return directory.resolve(aUid + SUFFIX);
    }

    private static void deleteQuietly(Path aFile) {
        try {
            Files.deleteIfExists(aFile);
        } catch (IOException e) {
            LOG.warn("Can't delete temp file {}", aFile.getFileName());
        }
    }
}
