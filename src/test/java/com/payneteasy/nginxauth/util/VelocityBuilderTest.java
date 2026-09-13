package com.payneteasy.nginxauth.util;

import com.payneteasy.nginxauth.servlet.LoginFormServlet;
import com.payneteasy.nginxauth.servlet.ShowLoginFormServlet;
import org.junit.Test;

import java.io.StringWriter;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class VelocityBuilderTest {

    @Test
    public void rendersLoginForm() throws Exception {
        StringWriter out = new StringWriter();
        new VelocityBuilder()
                .add("FORM_ACTION", "/auth/login")
                .add("BACK_URL_NAME", "back")
                .add("BACK_URL_VALUE", "/ok")
                .add("NONCE", "nonce-1")
                .add("OTP_ENABLED", Boolean.TRUE)
                .add("USERNAME", "alice&bob")
                .add("REASON", "<script>")
                .processTemplate(ShowLoginFormServlet.class, "/pages/login-form.vm", out);
        String html = out.toString();
        assertTrue(html.contains("value=\"/ok\""));
        assertTrue(html.contains("alice&amp;bob"));
        assertTrue(html.contains("&lt;script&gt;"));
        assertFalse(html.contains("<script>"));
    }

    @Test
    public void rendersChangePasswordForm() throws Exception {
        StringWriter out = new StringWriter();
        new VelocityBuilder()
                .add("BACK_URL_NAME", "back")
                .add("BACK_URL_VALUE", "/ok")
                .add("NONCE", "nonce-1")
                .add("OTP_ENABLED", Boolean.FALSE)
                .add("USERNAME", "alice")
                .add("REASON", "User must change password")
                .processTemplate(LoginFormServlet.class, "/pages/change-password-form.vm", out);
        String html = out.toString();
        assertTrue(html.contains("/auth/change-password"));
        assertTrue(html.contains("User must change password"));
        assertFalse(html.contains("j_code"));
    }
}
