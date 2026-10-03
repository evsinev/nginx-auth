package com.payneteasy.nginxauth.webauthn.storage;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class FileCredentialRepositoryTest {

    private Path dir;

    @Before
    public void setUp() throws IOException {
        dir = Files.createTempDirectory("repo-test").resolve("store");
    }

    @After
    public void tearDown() throws IOException {
        try (var walk = Files.walk(dir.getParent())) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    private static StoredCredential credential(String aId) {
        return new StoredCredential(aId, "cose", 0, "00000000-0000-0000-0000-000000000000", false, false, List.of("usb"), "key", 1000L, 0L);
    }

    private static void save(FileCredentialRepository aRepository, UserRecord aRecord) throws StorageException {
        aRepository.locks().withLock(aRecord.uid(), () -> {
            aRepository.save(aRecord);
            return null;
        });
    }

    @Test
    public void writeReadAndRestart() throws Exception {
        FileCredentialRepository repository = FileCredentialRepository.open(dir, new UserLocks());
        save(repository, UserRecord.empty("alice", "aGFuZGxl").withCredential(credential("Y3JlZDE")));

        FileCredentialRepository reopened = FileCredentialRepository.open(dir, new UserLocks());
        UserRecord record = reopened.find("alice").orElseThrow();
        assertEquals("aGFuZGxl", record.userHandle());
        assertEquals(Optional.of("alice"), reopened.ownerOfCredential("Y3JlZDE"));
        assertEquals(Optional.of("alice"), reopened.uidForUserHandle("aGFuZGxl"));
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(dir.resolve("alice.json"))));
        assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(dir)));
    }

    @Test
    public void saveRequiresUserLock() throws Exception {
        FileCredentialRepository repository = FileCredentialRepository.open(dir, new UserLocks());
        try {
            repository.save(UserRecord.empty("alice", "aGFuZGxl"));
            fail();
        } catch (IllegalStateException expected) {
            // ok
        }
    }

    @Test
    public void symlinkIsAStartupError() throws Exception {
        FileCredentialRepository.open(dir, new UserLocks());
        Path target = Files.createTempFile("target", ".json");
        Files.createSymbolicLink(dir.resolve("bob.json"), target);
        expectStartupError("Symlink");
        Files.delete(target);
    }

    @Test
    public void malformedJsonIsAStartupError() throws Exception {
        FileCredentialRepository.open(dir, new UserLocks());
        writeFile("bob.json", "{not json");
        expectStartupError("Malformed");
    }

    @Test
    public void unknownVersionIsAStartupError() throws Exception {
        FileCredentialRepository.open(dir, new UserLocks());
        writeFile("bob.json", "{\"version\":2,\"uid\":\"bob\",\"userHandle\":\"aA\",\"credentials\":[]}");
        expectStartupError("Malformed");
    }

    @Test
    public void duplicateCredentialIdAcrossFilesIsAStartupError() throws Exception {
        FileCredentialRepository repository = FileCredentialRepository.open(dir, new UserLocks());
        save(repository, UserRecord.empty("alice", "aGFuZGxl").withCredential(credential("Y3JlZDE")));
        String bob = new String(Files.readAllBytes(dir.resolve("alice.json")), StandardCharsets.UTF_8)
                .replace("\"alice\"", "\"bob\"").replace("aGFuZGxl", "b3RoZXI");
        writeFile("bob.json", bob);
        expectStartupError("Duplicate credential ID");
    }

    @Test
    public void groupReadableFileIsAStartupError() throws Exception {
        FileCredentialRepository repository = FileCredentialRepository.open(dir, new UserLocks());
        save(repository, UserRecord.empty("alice", "aGFuZGxl"));
        Files.setPosixFilePermissions(dir.resolve("alice.json"), PosixFilePermissions.fromString("rw-r-----"));
        expectStartupError("group/others");
    }

    @Test
    public void openDirectoryIsAStartupError() throws Exception {
        FileCredentialRepository.open(dir, new UserLocks());
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwxr-xr-x"));
        expectStartupError("group/others");
    }

    @Test
    public void leftoverTempFileIsRemoved() throws Exception {
        FileCredentialRepository.open(dir, new UserLocks());
        writeFile(".alice.123.json.tmp", "partial");
        FileCredentialRepository.open(dir, new UserLocks());
        assertFalse(Files.exists(dir.resolve(".alice.123.json.tmp")));
    }

    @Test
    public void parallelUpdatesOfOneUserKeepFileAndIndexConsistent() throws Exception {
        FileCredentialRepository repository = FileCredentialRepository.open(dir, new UserLocks());
        save(repository, UserRecord.empty("alice", "aGFuZGxl"));
        ExecutorService executor = Executors.newFixedThreadPool(8);
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
            String id = "Y3JlZC" + Integer.toString(i, 36);
            futures.add(executor.submit(() -> {
                repository.locks().withLock("alice", () -> {
                    UserRecord current = repository.find("alice").orElseThrow();
                    repository.save(current.withCredential(credential(id)));
                    return null;
                });
                return null;
            }));
        }
        for (Future<?> future : futures) {
            future.get(30, TimeUnit.SECONDS);
        }
        executor.shutdown();
        assertEquals(40, repository.find("alice").orElseThrow().credentials().size());
        FileCredentialRepository reopened = FileCredentialRepository.open(dir, new UserLocks());
        assertEquals(40, reopened.find("alice").orElseThrow().credentials().size());
    }

    @Test
    public void sameCredentialIdForTwoUsersConcurrently() throws Exception {
        UserLocks locks = new UserLocks();
        CountDownLatch bothWriting = new CountDownLatch(2);
        FileOps slow = new FileOps() {
            final DefaultFileOps delegate = new DefaultFileOps();

            @Override
            public void writeAndSync(Path aFile, byte[] aData) throws IOException {
                bothWriting.countDown();
                try {
                    bothWriting.await(200, TimeUnit.MILLISECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                delegate.writeAndSync(aFile, aData);
            }

            @Override
            public void atomicMove(Path aFrom, Path aTo) throws IOException {
                delegate.atomicMove(aFrom, aTo);
            }

            @Override
            public void syncDirectory(Path aDirectory) throws IOException {
                delegate.syncDirectory(aDirectory);
            }
        };
        FileCredentialRepository repository = FileCredentialRepository.open(dir, slow, locks);
        AtomicInteger saved = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();
        Thread[] threads = new Thread[2];
        String[] users = {"alice", "bob"};
        for (int i = 0; i < 2; i++) {
            String uid = users[i];
            String handle = i == 0 ? "aGFuZGxl" : "b3RoZXI";
            threads[i] = new Thread(() -> {
                try {
                    save(repository, UserRecord.empty(uid, handle).withCredential(credential("c2FtZQ")));
                    saved.incrementAndGet();
                } catch (DuplicateCredentialException e) {
                    rejected.incrementAndGet();
                } catch (StorageException e) {
                    throw new IllegalStateException(e);
                }
            });
            threads[i].start();
        }
        for (Thread thread : threads) {
            thread.join();
        }
        assertEquals(1, saved.get());
        assertEquals(1, rejected.get());
        String owner = repository.ownerOfCredential("c2FtZQ").orElseThrow();
        FileCredentialRepository reopened = FileCredentialRepository.open(dir, new UserLocks());
        assertEquals(Optional.of(owner), reopened.ownerOfCredential("c2FtZQ"));
    }

    @Test
    public void failureBeforeRenameKeepsOldStateAndReleasesReservation() throws Exception {
        FailingOps ops = new FailingOps();
        FileCredentialRepository repository = FileCredentialRepository.open(dir, ops, new UserLocks());
        save(repository, UserRecord.empty("alice", "aGFuZGxl"));
        ops.failWrite = true;
        try {
            save(repository, repository.find("alice").orElseThrow().withCredential(credential("Y3JlZDE")));
            fail();
        } catch (StorageException expected) {
            // ok
        }
        assertTrue(repository.find("alice").orElseThrow().credentials().isEmpty());
        assertFalse(repository.ownerOfCredential("Y3JlZDE").isPresent());
        assertFalse(repository.isFailed());
        ops.failWrite = false;
        save(repository, UserRecord.empty("bob", "b3RoZXI").withCredential(credential("Y3JlZDE")));
    }

    @Test
    public void renameFailureFollowsTheDisk() throws Exception {
        FailingOps ops = new FailingOps();
        FileCredentialRepository repository = FileCredentialRepository.open(dir, ops, new UserLocks());
        save(repository, UserRecord.empty("alice", "aGFuZGxl"));
        ops.failRenameAfterMove = true;
        try {
            save(repository, repository.find("alice").orElseThrow().withCredential(credential("Y3JlZDE")));
            fail();
        } catch (StorageException expected) {
            // ok
        }
        // the move happened before the error: cache follows the file
        assertEquals(1, repository.find("alice").orElseThrow().credentials().size());
        assertEquals(Optional.of("alice"), repository.ownerOfCredential("Y3JlZDE"));
        assertFalse(repository.isFailed());
    }

    @Test
    public void directoryFsyncFailureKeepsNewState() throws Exception {
        FailingOps ops = new FailingOps();
        FileCredentialRepository repository = FileCredentialRepository.open(dir, ops, new UserLocks());
        ops.failDirSync = true;
        save(repository, UserRecord.empty("alice", "aGFuZGxl").withCredential(credential("Y3JlZDE")));
        assertEquals(Optional.of("alice"), repository.ownerOfCredential("Y3JlZDE"));
        assertEquals(1, FileCredentialRepository.open(dir, new UserLocks()).find("alice").orElseThrow().credentials().size());
    }

    @Test
    public void invalidUidIsRejected() throws Exception {
        FileCredentialRepository repository = FileCredentialRepository.open(dir, new UserLocks());
        assertFalse(FileCredentialRepository.isValidUid("../etc"));
        assertFalse(FileCredentialRepository.isValidUid(".hidden"));
        assertFalse(FileCredentialRepository.isValidUid(""));
        assertTrue(FileCredentialRepository.isValidUid("john.doe@example.com"));
        try {
            save(repository, UserRecord.empty("../x", "aGFuZGxl"));
            fail();
        } catch (StorageException expected) {
            // ok
        }
    }

    private void writeFile(String aName, String aContent) throws IOException {
        Path file = dir.resolve(aName);
        Files.writeString(file, aContent);
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
    }

    private void expectStartupError(String aMessagePart) {
        try {
            FileCredentialRepository.open(dir, new UserLocks());
            fail("expected startup error");
        } catch (StorageException e) {
            assertTrue(e.getMessage(), e.getMessage().contains(aMessagePart));
        }
    }

    private static final class FailingOps implements FileOps {
        final DefaultFileOps delegate = new DefaultFileOps();
        volatile boolean failWrite;
        volatile boolean failRenameAfterMove;
        volatile boolean failDirSync;

        @Override
        public void writeAndSync(Path aFile, byte[] aData) throws IOException {
            if (failWrite) {
                throw new IOException("disk full");
            }
            delegate.writeAndSync(aFile, aData);
        }

        @Override
        public void atomicMove(Path aFrom, Path aTo) throws IOException {
            delegate.atomicMove(aFrom, aTo);
            if (failRenameAfterMove) {
                throw new IOException("rename reported failure");
            }
        }

        @Override
        public void syncDirectory(Path aDirectory) throws IOException {
            if (failDirSync) {
                throw new IOException("fsync failed");
            }
            delegate.syncDirectory(aDirectory);
        }
    }
}
