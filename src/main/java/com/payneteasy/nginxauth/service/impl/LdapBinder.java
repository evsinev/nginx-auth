package com.payneteasy.nginxauth.service.impl;

import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;

interface LdapBinder {
    InitialLdapContext bind(String dn, String password) throws NamingException;
}
