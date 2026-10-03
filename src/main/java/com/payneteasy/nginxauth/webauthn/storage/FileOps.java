package com.payneteasy.nginxauth.webauthn.storage;

import java.io.IOException;
import java.nio.file.Path;

/**
 * File operations used for a durable write; replaceable in tests for fault injection.
 */
public interface FileOps {

    /** Creates the file with mode 0600 (where supported), writes and fsyncs it. */
    void writeAndSync(Path aFile, byte[] aData) throws IOException;

    void atomicMove(Path aFrom, Path aTo) throws IOException;

    void syncDirectory(Path aDirectory) throws IOException;
}
