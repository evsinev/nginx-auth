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
        assertTrue(LoginNames.same("İstanbul", "i\u0307stanbul"));
        // compatibility forms that decompose to upper case, iota subscript
        assertTrue(LoginNames.same("\u2102lice", "Clice"));
        assertTrue(LoginNames.same("\u1F80", "\u1F00\u03B9"));
        // RFC 4518 §2.2 map: removed and space-mapped code points
        assertTrue(LoginNames.same("Alice", "Al\u00ADice"));
        assertTrue(LoginNames.same("Alice", "Al\u200Bice"));
        assertTrue(LoginNames.same("ab", "a\u001Cb"));
        assertTrue(LoginNames.same("a b", "a\u2003b"));
        assertFalse(LoginNames.same("a b", "ab"));
        // coarser than LDAP on purpose: only revocation and the limiter use it
        assertTrue(LoginNames.same("ıpek", "ipek"));
        assertTrue(LoginNames.same("ıPEK", "ıpek"));
        assertFalse(LoginNames.same("olga smith", "olgasmith"));
        assertFalse(LoginNames.same(null, "x"));
    }
}
