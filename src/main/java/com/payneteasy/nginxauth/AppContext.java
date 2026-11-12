package com.payneteasy.nginxauth;

import com.payneteasy.nginxauth.service.IAuthService;
import com.payneteasy.nginxauth.service.INonceManager;
import com.payneteasy.nginxauth.service.IOneTimePasswordService;
import com.payneteasy.nginxauth.service.ITokenManager;
import com.payneteasy.nginxauth.service.impl.AuthServiceImpl;
import com.payneteasy.nginxauth.service.impl.NonceManagerImpl;
import com.payneteasy.nginxauth.service.impl.OneTimePasswordServiceImpl;
import com.payneteasy.nginxauth.service.impl.TokenManagerImpl;
import com.payneteasy.nginxauth.util.SettingsManager;
import com.payneteasy.nginxauth.webauthn.WebAuthnConfig;
import com.payneteasy.nginxauth.webauthn.WebAuthnContext;
import com.payneteasy.nginxauth.webauthn.storage.StorageException;

/**
 * Services shared by the servlets. {@link #webauthn()} is null when WEBAUTHN_ENABLED=false.
 */
public final class AppContext {

    private final boolean                 otpEnabled;
    private final IAuthService            authService;
    private final IOneTimePasswordService otpService;
    private final ITokenManager           tokens;
    private final INonceManager           nonces;
    private final WebAuthnContext         webauthn;

    public AppContext(boolean aOtpEnabled, IAuthService aAuthService, IOneTimePasswordService aOtpService, ITokenManager aTokens,
                      INonceManager aNonces, WebAuthnContext aWebauthn) {
        otpEnabled  = aOtpEnabled;
        authService = aAuthService;
        otpService  = aOtpService;
        tokens      = aTokens;
        nonces      = aNonces;
        webauthn    = aWebauthn;
    }

    public static AppContext fromSettings() throws StorageException {
        WebAuthnConfig config = WebAuthnConfig.fromSettings();
        ITokenManager tokens = TokenManagerImpl.getInstance();
        WebAuthnContext webauthn = config.isEnabled() ? WebAuthnContext.open(config, tokens) : null;
        return new AppContext(
                SettingsManager.isOtpEnabled(),
                new AuthServiceImpl(),
                OneTimePasswordServiceImpl.getInstance(),
                tokens,
                NonceManagerImpl.getInstance(),
                webauthn);
    }

    public boolean otpEnabled() {
        return otpEnabled;
    }

    public IAuthService authService() {
        return authService;
    }

    public IOneTimePasswordService otpService() {
        return otpService;
    }

    public ITokenManager tokens() {
        return tokens;
    }

    public INonceManager nonces() {
        return nonces;
    }

    public WebAuthnContext webauthn() {
        return webauthn;
    }
}
