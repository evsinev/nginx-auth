package com.payneteasy.nginxauth.service.impl;

import com.payneteasy.ldap.users.impl.DirectoryServiceImpl;
import com.payneteasy.ldap.users.model.LdapQuery;
import com.payneteasy.ldap.users.model.LdapQueryHolder;
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
import java.util.Map;
import java.util.Properties;

import static com.payneteasy.nginxauth.util.StringUtils.escapeDN;

/**
 *
 */
public class AuthServiceImpl implements IAuthService {

    private static final Logger LOG = LoggerFactory.getLogger(AuthServiceImpl.class);

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
            throw new AuthenticationException(e.getLocalizedMessage());

        } catch (NoPermissionException e) {
            // http://blogs.nologin.es/rickyepoderi/index.php/archives/57-LDAP-password-policies-and-JavaEE.html
            LOG.error("User must change password: " + e.getExplanation());
            throw new UserMustChangePasswordException();

        } catch (NamingException e) {
            LOG.error("Can't connect to ldap: " + e.getExplanation(), e);
            throw new AuthenticationException(e.getExplanation());
        }
    }

    private InitialLdapContext createInitialLdapContext(String aUsername, String aPassword) throws NamingException {
        String user = getUserCommonName(aUsername);
        LOG.debug("Connecting to ldap with {}...", user);

        Properties env = new Properties();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL           , SettingsManager.getLdapUrl());
        env.put(Context.SECURITY_PRINCIPAL     , user);
        env.put(Context.SECURITY_CREDENTIALS   , aPassword);

        return new InitialLdapContext(env, null);
    }

    private String getUserCommonName(String aUsername) {
        return String.format("cn=%s,%s"
                    , escapeDN(aUsername)
                    , SettingsManager.getLdapUsersDn()
            );
    }

    private void checkAccess(String aUsername, InitialLdapContext context, boolean aCanCheckAccess) throws NamingException {
        DirectoryServiceImpl directoryService = new DirectoryServiceImpl(context);
        LdapQueryHolder queryHolder = new LdapQueryHolder(aUsername, SettingsManager.getLdapUsersDn());
        LdapQuery ldapQuery = queryHolder.find("user-info");
        if(aCanCheckAccess) {
            Map<String, Object> result = directoryService.get("cn="+aUsername+","+SettingsManager.getLdapUsersDn(), ldapQuery.attributes);
        }
    }

    @Override
    public void authenticate(String aUsername, String aPassword, long aCode, boolean aCanCheckAccess) throws AuthenticationException, UserMustChangePasswordException {

        authenticate(aUsername, aPassword, aCanCheckAccess);

        if (!theOneTimePasswordService.checkCode(aUsername, aCode)) {
            throw new AuthenticationException("Verification code is invalid");
        }
    }

    private IOneTimePasswordService theOneTimePasswordService = new OneTimePasswordServiceImpl();

    public void changePassword(String aUsername, String aCurrentPassword, String aNewPassword) throws AuthenticationException {
        try {

            InitialLdapContext context = createInitialLdapContext(aUsername, aCurrentPassword);
            try {

                ModificationItem[] modificationItems = {
                        new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute("userPassword", aCurrentPassword)),
                        new ModificationItem(DirContext.ADD_ATTRIBUTE   , new BasicAttribute("userPassword", aNewPassword))
                };

                context.modifyAttributes(getUserCommonName(aUsername), modificationItems);
            } finally {
                context.close();
            }
        } catch (CommunicationException e) {
            LOG.error("Can't connect to ldap: "+e.getExplanation(), e);
            throw new AuthenticationException("Can't connect to ldap server");

        } catch (AuthenticationException e) {
            LOG.error("Can't connect to ldap: "+e.getLocalizedMessage());
            throw new AuthenticationException(e.getLocalizedMessage());

        } catch (NamingException e) {
            LOG.error("Can't connect to ldap: " + e.getExplanation(), e);
            throw new AuthenticationException(e.getExplanation());
        }
    }

}
