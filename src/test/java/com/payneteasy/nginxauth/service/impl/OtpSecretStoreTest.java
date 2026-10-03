package com.payneteasy.nginxauth.service.impl;

import org.apache.commons.codec.binary.Base32;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.attribute.FileTime;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class OtpSecretStoreTest {

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Test
    public void constructorDoesNotReadFile() throws Exception {
        File file = folder.newFile("otp.properties");
        Files.write(file.toPath(), "alice=SECRET\n".getBytes(StandardCharsets.UTF_8));
        OtpSecretStore store = new OtpSecretStore(file.toPath(), 5_000L, System::currentTimeMillis);
        assertEquals(0, store.loadCount());
        store.dummySecret();
        assertEquals(0, store.loadCount());
    }

    @Test
    public void getSecretLoadsOnceUntilMtimeAndIntervalPass() throws Exception {
        File file = folder.newFile("otp.properties");
        Files.write(file.toPath(), "alice=ONE\n".getBytes(StandardCharsets.UTF_8));
        AtomicLong now = new AtomicLong(1_000L);
        OtpSecretStore store = new OtpSecretStore(file.toPath(), 5_000L, now::get);

        for (int i = 0; i < 100; i++) {
            assertEquals("ONE", store.getSecret("alice"));
        }
        assertEquals(1, store.loadCount());

        Files.write(file.toPath(), "alice=TWO\n".getBytes(StandardCharsets.UTF_8));
        Files.setLastModifiedTime(file.toPath(), FileTime.fromMillis(now.get() + 10_000L));
        now.addAndGet(6_000L);
        assertEquals("TWO", store.getSecret("alice"));
        assertEquals(2, store.loadCount());
    }

    @Test
    public void missingFileReturnsNullWithoutThrowing() {
        OtpSecretStore store = new OtpSecretStore(
                folder.getRoot().toPath().resolve("missing.properties"),
                5_000L,
                System::currentTimeMillis
        );
        assertNull(store.getSecret("alice"));
        assertEquals(1, store.loadCount());
    }

    @Test
    public void dummySecretIsStableBase32() {
        OtpSecretStore store = new OtpSecretStore(
                folder.getRoot().toPath().resolve("unused.properties"),
                5_000L,
                System::currentTimeMillis
        );
        String first = store.dummySecret();
        String second = store.dummySecret();
        assertEquals(first, second);
        assertNotNull(first);
        assertTrue(first.length() > 0);
        byte[] decoded = new Base32().decode(first);
        assertEquals(20, decoded.length);
        assertNotEquals(first, new OtpSecretStore(
                folder.getRoot().toPath().resolve("other.properties"),
                5_000L,
                System::currentTimeMillis
        ).dummySecret());
    }
}
