package com.payneteasy.nginxauth.ldap;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class LoginNamesTest {

    @Test
    public void spellingsOfOneDnCompareEqual() {
        assertEquals("olga smith", LoginNames.normalize("  Olga \t Smith "));
        assertTrue(LoginNames.same("Olga Smith", "olga  smith"));
        assertTrue(LoginNames.same("Olga Smith", "olga smith"));
        assertTrue(LoginNames.same("ＡＬＩＣＥ", "alice"));
        assertFalse(LoginNames.same("olga smith", "olgasmith"));
        assertFalse(LoginNames.same(null, "x"));
    }
}
