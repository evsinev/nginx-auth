package com.payneteasy.nginxauth.servlet;

import com.payneteasy.nginxauth.service.INonceManager;
import com.payneteasy.nginxauth.util.VelocityBuilder;
import org.junit.Test;

import java.io.StringWriter;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class LoginFormServletNonceTest {

    @Test
    public void capShowsServiceBusyInsteadOfLiteralNonce() throws Exception {
        INonceManager exhausted = new INonceManager() {
            @Override
            public String addNonce() {
                return null;
            }

            @Override
            public boolean checkNonce(String aNonce) {
                return false;
            }
        };

        StringWriter out = new StringWriter();
        VelocityBuilder velocity = new VelocityBuilder();
        velocity.add("FORM_ACTION", "/auth/login");
        velocity.add("BACK_URL_NAME", "back");
        velocity.add("BACK_URL_VALUE", "/ok");
        velocity.add("OTP_ENABLED", Boolean.FALSE);
        LoginFormServlet.putNonce(velocity, exhausted);
        velocity.processTemplate(ShowLoginFormServlet.class, "/pages/login-form.vm", out);

        String html = out.toString();
        assertTrue(html.contains("Service busy"));
        assertFalse(html.contains("$NONCE"));
        assertTrue(html.contains("name=\"j_nonce\" value=\"\""));
    }
}
