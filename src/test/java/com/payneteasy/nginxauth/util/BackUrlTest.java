package com.payneteasy.nginxauth.util;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class BackUrlTest {

    @Test
    public void acceptsRelativePathWithQuery() {
        assertEquals("/a?b=1", BackUrl.normalize("/a?b=1").get());
    }

    @Test
    public void rejectsAbsoluteAndDangerousValues() {
        assertFalse(BackUrl.normalize("https://evil").isPresent());
        assertFalse(BackUrl.normalize("//evil").isPresent());
        assertFalse(BackUrl.normalize("/\\evil").isPresent());
        assertFalse(BackUrl.normalize("javascript:alert(1)").isPresent());
        assertFalse(BackUrl.normalize("/ok\r\n").isPresent());
        assertFalse(BackUrl.normalize("").isPresent());
        assertFalse(BackUrl.normalize(null).isPresent());
    }

    @Test
    public void rejectsControlCharacters() {
        assertFalse(BackUrl.normalize("/ok\n").isPresent());
        assertFalse(BackUrl.normalize("/ok\t").isPresent());
    }

    @Test
    public void acceptsPlainRelativePath() {
        assertTrue(BackUrl.normalize("/ok").isPresent());
    }
}
