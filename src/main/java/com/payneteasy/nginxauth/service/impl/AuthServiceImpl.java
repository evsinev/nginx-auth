package com.payneteasy.nginxauth.service.impl;

import com.payneteasy.nginxauth.service.IAuthService;
import com.payneteasy.nginxauth.service.IOneTimePasswordService;
import com.payneteasy.nginxauth.service.UserMustChangePasswordException;
import com.payneteasy.nginxauth.util.SettingsManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.*;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.ldap.InitialLdapContext;
import java.util.Properties;

import static com.payneteasy.nginxauth.util.StringUtils.escapeDN;

/**
 *
 */
public class AuthServiceImpl implements IAuthService {

    private static final Logger LOG = LoggerFactory.getLogger(AuthServiceImpl.class);

    private static final String[] USER_INFO_ATTRS = {
            "cn", "gecos", "uid", "uidNumber", "authTimestamp", "pwdFailedTime",
            "pwdChangedTime", "pwdReset", "pwdFailureTime", "pwdAccountLockedTime", "host"
    };

    public AuthServiceImpl() {
        this(OneTimePasswordServiceImpl.getInstance(), AuthServiceImpl::bind);
    }

    AuthServiceImpl(IOneTimePasswordService otp, LdapBinder binder) {
        this.theOneTimePasswordService = otp;
        this.theLdapBinder = binder;
    }

    @Override
    public void authenticate(String aUsername, String aPassword, boolean aCanCheckAccess) throws AuthenticationException, UserMustChangePasswordException {
        try {
            InitialLdapContext context = createInitialLdapContext(aUsername, aPassword);
            try {
                checkAccess(aUsername, context, aCanCheckAccess);
            } finally {
                context.close();
            }

        } catch (CommunicationException e) {
            LOG.error("Can't connect to ldap: "+e.getExplanation(), e);
            throw new AuthenticationException("Can't connect to ldap server");

        } catch (AuthenticationException e) {
            LOG.error("Can't connect to ldap: "+e.getLocalizedMessage());
            throw new AuthenticationException("Authentication failed");

        } catch (NoPermissionException e) {
            // http://blogs.nologin.es/rickyepoderi/index.php/archives/57-LDAP-password-policies-and-JavaEE.html
            LOG.error("User must change password: " + e.getExplanation());
            throw new UserMustChangePasswordException();

        } catch (NamingException e) {
            LOG.error("Can't connect to ldap: " + e.getExplanation(), e);
            throw new AuthenticationException("Authentication failed");
        }
    }

    private InitialLdapContext createInitialLdapContext(String aUsername, String aPassword) throws NamingException {
        return theLdapBinder.bind(buildUserDn(aUsername), aPassword);
    }

    private static InitialLdapContext bind(String dn, String password) throws NamingException {
        LOG.debug("Connecting to ldap with {}...", dn);

        Properties env = new Properties();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL           , SettingsManager.getLdapUrl());
        env.put(Context.SECURITY_PRINCIPAL     , dn);
        env.put(Context.SECURITY_CREDENTIALS   , password);

        return new InitialLdapContext(env, null);
    }

    private String buildUserDn(String aUsername) {
        return String.format("cn=%s,%s"
                    , escapeDN(aUsername)
                    , SettingsManager.getLdapUsersDn()
            );
    }

    private void checkAccess(String aUsername, InitialLdapContext context, boolean aCanCheckAccess) throws NamingException {
        if (aCanCheckAccess) {
            context.getAttributes(buildUserDn(aUsername), USER_INFO_ATTRS);
        }
    }

    @Override
    public void authenticate(String aUsername, String aPassword, long aCode, boolean aCanCheckAccess) throws AuthenticationException, UserMustChangePasswordException {

        try {
            authenticate(aUsername, aPassword, aCanCheckAccess);
        } catch (AuthenticationException e) {
            theOneTimePasswordService.dummyCheck(aCode);
            throw e;
        }

        if (!theOneTimePasswordService.checkCode(aUsername, aCode)) {
            LOG.debug("OTP verification failed for user {}", aUsername);
            throw new AuthenticationException("Authentication failed");
        }
    }

    private final IOneTimePasswordService theOneTimePasswordService;
    private final LdapBinder theLdapBinder;

    public void changePassword(String aUsername, String aCurrentPassword, String aNewPassword) throws AuthenticationException {
        try {

            InitialLdapContext context = createInitialLdapContext(aUsername, aCurrentPassword);
            try {

                ModificationItem[] modificationItems = {
                        new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute("userPassword", aCurrentPassword)),
                        new ModificationItem(DirContext.ADD_ATTRIBUTE   , new BasicAttribute("userPassword", aNewPassword))
                };

                context.modifyAttributes(buildUserDn(aUsername), modificationItems);
            } finally {
                context.close();
            }
        } catch (CommunicationException e) {
            LOG.error("Can't connect to ldap: "+e.getExplanation(), e);
            throw new AuthenticationException("Can't connect to ldap server");

        } catch (AuthenticationException e) {
            LOG.error("Can't connect to ldap: "+e.getLocalizedMessage());
            throw new AuthenticationException("Password change failed");

        } catch (NamingException e) {
            LOG.error("Can't connect to ldap: " + e.getExplanation(), e);
            throw new AuthenticationException("Password change failed");
        }
    }

}
