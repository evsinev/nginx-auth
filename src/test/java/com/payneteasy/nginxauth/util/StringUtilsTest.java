package com.payneteasy.nginxauth.util;

import org.junit.Assert;
import org.junit.Test;

import static com.payneteasy.nginxauth.util.StringUtils.escapeDN;
import static com.payneteasy.nginxauth.util.StringUtils.escapeLDAPSearchFilter;
import static org.junit.Assert.assertEquals;

public class StringUtilsTest {

    @Test
    public void testEscapeDN() {
        assertEquals("No special characters to escape", "Helloé", escapeDN("Helloé"));
        assertEquals("leading #", "\\# Helloé", escapeDN("# Helloé"));
        assertEquals("leading space", "\\ Helloé", escapeDN(" Helloé"));
        assertEquals("trailing space", "Helloé\\ ", escapeDN("Helloé "));
        assertEquals("only 3 spaces", "\\  \\ ", escapeDN("   "));
        assertEquals("Christmas Tree DN", "\\ Hello\\\\ \\+ \\, \\\"World\\\" \\;\\ ", escapeDN(" Hello\\ + , \"World\" ; "));
    }

    @Test
    public void tesEscapeLDAPSearchFilter() {
        assertEquals("No special characters to escape", "Hi This is a test #çà", escapeLDAPSearchFilter("Hi This is a test #çà"));
        assertEquals("LDAP Christams Tree", "Hi \\28This\\29 = is \\2a a \\5c test # ç à ô", escapeLDAPSearchFilter("Hi (This) = is * a \\ test # ç à ô"));
    }

    @Test
    public void testEscapeInvalidSymbols(){
        String escapedBackUrl = StringUtils.escape("http://google.com/\"<script src=\"http://evil.com/dangerous.js\" type=\"text/javascript\" charset=\"utf-8\"></script>");
        Assert.assertFalse(escapedBackUrl.contains(">"));
        Assert.assertFalse(escapedBackUrl.contains("<"));
        Assert.assertFalse(escapedBackUrl.contains("\""));
    }
}
