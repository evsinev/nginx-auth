package com.payneteasy.nginxauth.service;

public enum AuthenticationMethod {
    LDAP_ONLY,
    LDAP_TOTP,
    LDAP_WEBAUTHN
}
