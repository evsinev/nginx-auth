package com.payneteasy.nginxauth.servlet;

import org.junit.Test;

import static org.junit.Assert.assertThrows;

public class IdentityHeadersTest {

    @Test
    public void invalidHeaderNameFailsStartup() {
        assertThrows(IllegalStateException.class, () -> new IdentityHeaders("X-Auth User", "X-Auth-Groups"));
        assertThrows(IllegalStateException.class, () -> new IdentityHeaders("X-Auth-User", "X-Auth-Groups:"));
        assertThrows(IllegalStateException.class, () -> new IdentityHeaders("X-Auth-User\r\nX-Injected", ""));
    }

    @Test
    public void emptyHeaderNamesAreAllowed() {
        new IdentityHeaders("", "");
    }
}
