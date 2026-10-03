package com.payneteasy.nginxauth.servlet;

import com.payneteasy.nginxauth.AppContext;
import com.payneteasy.nginxauth.service.ITokenManager;
import com.payneteasy.nginxauth.service.Session;
import com.payneteasy.nginxauth.util.CookiesManager;
import com.payneteasy.nginxauth.util.HttpRequestUtil;
import com.payneteasy.nginxauth.util.SettingsManager;
import com.payneteasy.nginxauth.util.VelocityBuilder;
import com.payneteasy.nginxauth.webauthn.Audit;
import com.payneteasy.nginxauth.webauthn.BrowserStateStore.BrowserState;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

public class LogoutServlet extends HttpServlet {

    private final ITokenManager tokenManager;
    private final WebAuthnWeb   web;

    public LogoutServlet(AppContext aApp) {
        tokenManager = aApp.tokens();
        web = aApp.webauthn() == null ? null : new WebAuthnWeb(aApp);
    }

    @Override
    protected void doGet(HttpServletRequest aRequest, HttpServletResponse aResponse) throws ServletException, IOException {
        if (web != null) {
            // state change only by POST with CSRF; GET shows the confirmation form
            HttpRequestUtil.logDebug(aRequest);
            Optional<BrowserState> state = web.ensureBinding(aRequest, aResponse);
            VelocityBuilder velocity = web.page(state.orElse(null));
            web.render(aResponse, velocity, "/pages/logout-confirm.vm");
            return;
        }
        logout(aRequest, aResponse);
    }

    @Override
    protected void doPost(HttpServletRequest aRequest, HttpServletResponse aResponse) throws ServletException, IOException {
        if (web != null) {
            Optional<BrowserState> state = web.existingBinding(aRequest);
            if (web.postOrigin(aRequest).isEmpty() || state.isEmpty()
                    || !web.checkCsrf(state.get(), aRequest.getParameter(WebAuthnWeb.CSRF_PARAM))) {
                Audit.log("csrf_rejected", "path", aRequest.getRequestURI(), "ip", HttpRequestUtil.clientIp(aRequest));
                web.message(aResponse, HttpServletResponse.SC_FORBIDDEN, "Request rejected", "Please use the logout button.", WebAuthnWeb.AUTH_URL + "/logout", "Logout");
                return;
            }
            web.webauthn().states().clearPreAuth(state.get(), null);
            web.webauthn().transactions().cancelForBinding(state.get().binding());
        }
        logout(aRequest, aResponse);
    }

    private void logout(HttpServletRequest aRequest, HttpServletResponse aResponse) throws IOException {
        HttpRequestUtil.logDebug(aRequest);
        HttpRequestUtil.setNoStoreHeaders(aResponse);

        CookiesManager cookies = new CookiesManager(aRequest, aResponse);
        String token = cookies.getCookieValue(SettingsManager.getTokenCookieName());
        Optional<Session> session = tokenManager.peekSession(token);
        if (web != null && session.isPresent()) {
            // same lock as ceremony commits, so a logout cannot slip between their check and publication
            web.webauthn().repository().locks().withLock(session.get().getCanonicalUid(), () -> {
                tokenManager.invalidateToken(token);
                return null;
            });
        } else {
            tokenManager.invalidateToken(token);
        }
        cookies.clear();

        VelocityBuilder velocity = new VelocityBuilder();
        velocity.processTemplate(LogoutServlet.class, "/pages/logout-form.vm.html", aResponse.getWriter());
    }
}
