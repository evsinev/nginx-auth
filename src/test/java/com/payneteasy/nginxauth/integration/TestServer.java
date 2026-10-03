package com.payneteasy.nginxauth.integration;

import com.payneteasy.nginxauth.AppContext;
import com.payneteasy.nginxauth.WebServer;
import com.payneteasy.nginxauth.ldap.LdapPrincipal;
import com.payneteasy.nginxauth.policy.PolicySet;
import com.payneteasy.nginxauth.service.IAuthService;
import com.payneteasy.nginxauth.service.IOneTimePasswordService;
import com.payneteasy.nginxauth.service.UserMustChangePasswordException;
import com.payneteasy.nginxauth.service.impl.NonceManagerImpl;
import com.payneteasy.nginxauth.service.impl.TokenManagerImpl;
import com.payneteasy.nginxauth.webauthn.WebAuthnConfig;
import com.payneteasy.nginxauth.webauthn.WebAuthnContext;
import com.payneteasy.nginxauth.webauthn.storage.FileCredentialRepository;
import com.payneteasy.nginxauth.webauthn.storage.UserLocks;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;

import javax.naming.AuthenticationException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Real Jetty with the production servlets, a fake LDAP and a fake TOTP.
 */
final class TestServer implements AutoCloseable {

    static final String ADMIN_TOKEN = "0123456789abcdef0123456789abcdef-admin";
    static final String TOTP_CODE   = "123456";

    final Map<String, String>       passwords    = new ConcurrentHashMap<>();
    final Map<String, List<String>> groups       = new ConcurrentHashMap<>();
    final Map<String, Boolean>      mustChange   = new ConcurrentHashMap<>();
    final Map<String, Boolean>      totpUsers    = new ConcurrentHashMap<>();
    volatile boolean                failPrincipalAfterChange;

    final Path            dir;
    final AppContext      app;
    final WebAuthnContext webauthn;
    final Server          server;
    final int             port;
    final int             adminPort;

    TestServer(boolean aWebAuthn, PolicySet aPolicies, boolean aOtpEnabled) throws Exception {
        dir = Files.createTempDirectory("nginx-auth-it").resolve("store");
        TokenManagerImpl tokens = new TokenManagerImpl(15 * 60 * 1000L, System::currentTimeMillis);
        if (aWebAuthn) {
            WebAuthnConfig config = WebAuthnConfig.builder()
                    .enabled(true)
                    .rpId("example.com")
                    .allowedOrigins("https://app1.example.com,https://app2.example.com")
                    .storageDir(dir)
                    .policies(aPolicies)
                    .adminToken(ADMIN_TOKEN)
                    .adminPort(0)
                    .build();
            webauthn = new WebAuthnContext(config, FileCredentialRepository.open(dir, new UserLocks()), tokens, System::currentTimeMillis);
        } else {
            webauthn = null;
        }
        app = new AppContext(aOtpEnabled, new FakeAuth(), new FakeOtp(), tokens, NonceManagerImpl.getInstance(), webauthn);
        server = WebServer.createServer(app, 0);
        server.start();
        int main = -1;
        int admin = -1;
        for (Connector connector : server.getConnectors()) {
            ServerConnector serverConnector = (ServerConnector) connector;
            if ("admin".equals(serverConnector.getName())) {
                admin = serverConnector.getLocalPort();
            } else {
                main = serverConnector.getLocalPort();
            }
        }
        port = main;
        adminPort = admin;
    }

    void user(String aUid, String aPassword, String... aGroups) {
        passwords.put(aUid, aPassword);
        groups.put(aUid, List.of(aGroups));
    }

    @Override
    public void close() throws Exception {
        server.stop();
        try (var walk = Files.walk(dir.getParent())) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    private final class FakeAuth implements IAuthService {

        private void check(String aUsername, String aPassword) throws AuthenticationException {
            if (aPassword == null || !aPassword.equals(passwords.get(aUsername))) {
                throw new AuthenticationException("Authentication failed");
            }
        }

        @Override
        public void authenticate(String aUsername, String aPassword, long aCode, boolean aCanCheckAccess) throws AuthenticationException, UserMustChangePasswordException {
            authenticate(aUsername, aPassword, aCanCheckAccess);
            if (!(Boolean.TRUE.equals(totpUsers.get(aUsername)) && aCode == Long.parseLong(TOTP_CODE))) {
                throw new AuthenticationException("Authentication failed");
            }
        }

        @Override
        public void authenticate(String aUsername, String aPassword, boolean aCanCheckAccess) throws AuthenticationException, UserMustChangePasswordException {
            check(aUsername, aPassword);
            if (aCanCheckAccess && Boolean.TRUE.equals(mustChange.get(aUsername))) {
                throw new UserMustChangePasswordException();
            }
        }

        @Override
        public LdapPrincipal authenticatePrincipal(String aUsername, String aPassword) throws AuthenticationException, UserMustChangePasswordException {
            check(aUsername, aPassword);
            if (Boolean.TRUE.equals(mustChange.get(aUsername))) {
                throw new UserMustChangePasswordException();
            }
            return new LdapPrincipal(aUsername, aUsername, groups.getOrDefault(aUsername, List.of()), System.currentTimeMillis());
        }

        @Override
        public void changePassword(String aUsername, String aCurrentPassword, String aNewPassword) throws AuthenticationException {
            check(aUsername, aCurrentPassword);
            passwords.put(aUsername, aNewPassword);
            mustChange.remove(aUsername);
            if (failPrincipalAfterChange) {
                passwords.put(aUsername, aNewPassword + "-unreadable");
            }
        }
    }

    private final class FakeOtp implements IOneTimePasswordService {
        @Override
        public boolean checkCode(String aUsername, long aCode) {
            return Boolean.TRUE.equals(totpUsers.get(aUsername)) && aCode == Long.parseLong(TOTP_CODE);
        }

        @Override
        public void dummyCheck(long aCode) {
        }

        @Override
        public boolean hasSecret(String aUsername) {
            return Boolean.TRUE.equals(totpUsers.get(aUsername));
        }
    }
}
