package com.payneteasy.nginxauth.webauthn.storage;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.EnumSet;

public final class DefaultFileOps implements FileOps {

    static final boolean POSIX = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");

    @Override
    public void writeAndSync(Path aFile, byte[] aData) throws IOException {
        FileAttribute<?>[] attributes = POSIX
                ? new FileAttribute<?>[] { PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")) }
                : new FileAttribute<?>[0];
        try (FileChannel channel = FileChannel.open(aFile,
                EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), attributes)) {
            ByteBuffer buffer = ByteBuffer.wrap(aData);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            channel.force(true);
        }
    }

    @Override
    public void atomicMove(Path aFrom, Path aTo) throws IOException {
        Files.move(aFrom, aTo, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    @Override
    public void syncDirectory(Path aDirectory) throws IOException {
        try (FileChannel channel = FileChannel.open(aDirectory, StandardOpenOption.READ)) {
            channel.force(true);
        }
    }
}
