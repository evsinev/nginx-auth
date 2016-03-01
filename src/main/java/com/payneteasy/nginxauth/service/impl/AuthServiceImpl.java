package com.payneteasy.nginxauth.service.impl;

import com.payneteasy.nginxauth.service.IAuthService;
import com.payneteasy.nginxauth.service.IOneTimePasswordService;
import com.payneteasy.nginxauth.util.SettingsManager;
import com.payneteasy.nginxauth.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import java.util.Properties;

import static com.payneteasy.nginxauth.util.StringUtils.escapeDN;

/**
 *
 */
public class AuthServiceImpl implements IAuthService {

    private static final Logger LOG = LoggerFactory.getLogger(AuthServiceImpl.class);

    @Override
    public void authenticate(String aUsername, String aPassword, long aCode) throws AuthenticationException {

        String user = String.format("cn=%s,%s"
                , escapeDN(aUsername)
                , SettingsManager.getLdapUsersDn()
        );
        LOG.debug("Connecting to ldap with {}...", user);

        Properties env = new Properties();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, SettingsManager.getLdapUrl());
        env.put(Context.SECURITY_PRINCIPAL, user);
        env.put(Context.SECURITY_CREDENTIALS, aPassword);

        try {
            InitialLdapContext context = new InitialLdapContext(env, null);
            context.close();
        } catch (CommunicationException e) {
            LOG.error("Can't connect to ldap: "+e.getExplanation(), e);
            throw new AuthenticationException("Can't connect to ldap server");

        } catch (AuthenticationException e) {
            LOG.error("Can't connect to ldap: "+e.getLocalizedMessage());
            throw new AuthenticationException(e.getLocalizedMessage());

        } catch (NamingException e) {
            LOG.error("Can't connect to ldap: "+e.getExplanation(), e);
            throw new AuthenticationException(e.getExplanation());
        }

        if(!theOneTimePasswordService.checkCode(aUsername, aCode)) {
            throw new AuthenticationException("Verification code is invalid");
        }

    }

    private IOneTimePasswordService theOneTimePasswordService = new OneTimePasswordServiceImpl();
}
