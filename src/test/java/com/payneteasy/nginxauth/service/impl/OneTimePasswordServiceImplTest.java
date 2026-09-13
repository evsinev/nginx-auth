package com.payneteasy.nginxauth.service.impl;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class OneTimePasswordServiceImplTest {

    @Test
    public void replayOfSameCodeIsRejected() {
        Map<String, String> secrets = new HashMap<String, String>();
        secrets.put("alice", "JBSWY3DPEHPK3PXP");
        AtomicLong now = new AtomicLong(1_700_000_000_000L);
        OneTimePasswordServiceImpl service = new OneTimePasswordServiceImpl(secrets::get, now::get);

        int code = service.codeAt(secrets.get("alice"), now.get());
        assertTrue(service.checkCode("alice", code));
        assertFalse(service.checkCode("alice", code));
    }

    @Test
    public void unknownUserIsRejected() {
        OneTimePasswordServiceImpl service = new OneTimePasswordServiceImpl(username -> null, System::currentTimeMillis);
        assertFalse(service.checkCode("nobody", 123456L));
    }
}
