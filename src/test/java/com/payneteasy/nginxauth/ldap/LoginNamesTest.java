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
        // RFC 3454 B.2 folds
        assertTrue(LoginNames.same("Straße", "STRASSE"));
        assertTrue(LoginNames.same("ſam", "SAM"));
        assertTrue(LoginNames.same("ὀδυσσεύς", "ὈΔΥΣΣΕΎΣ"));
        // distinct LDAP logins never merge
        assertFalse(LoginNames.same("ıpek", "ipek"));
        assertFalse(LoginNames.same("ıPEK", "ipek"));
        assertTrue(LoginNames.same("ıPEK", "ıpek"));
        assertFalse(LoginNames.same("olga smith", "olgasmith"));
        assertFalse(LoginNames.same(null, "x"));
    }
}
