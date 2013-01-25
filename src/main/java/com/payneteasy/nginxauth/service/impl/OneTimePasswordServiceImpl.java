package com.payneteasy.nginxauth.service.impl;

import com.payneteasy.nginxauth.service.IOneTimePasswordService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

/**
 * http://thegreyblog.blogspot.ru/2011/12/google-authenticator-using-it-in-your.html
 *
 */
public class OneTimePasswordServiceImpl implements IOneTimePasswordService {
    private static final Logger LOG = LoggerFactory.getLogger(OneTimePasswordServiceImpl.class);

    public OneTimePasswordServiceImpl() {
        theGoogleAuthenticator.setWindowSize(5);
    }

    @Override
    public boolean checkCode(String aUsername, long aCode) {
        try {
            FileInputStream in = new FileInputStream("otp.properties");
            try {
                Properties properties = new Properties();
                properties.load(in);
                String secret = properties.getProperty(aUsername);
                if(secret==null) {
                    LOG.warn("Can't find secret for user {}", aUsername);
                    return false;
                } else {
                    return theGoogleAuthenticator.check_code(properties.getProperty(aUsername), aCode, System.currentTimeMillis());

                }

            } finally {
                in.close();
            }
        } catch (IOException e) {
            LOG.error("Can't read otp.properties");
            return false;
        }
    }

    private final GoogleAuthenticator theGoogleAuthenticator = new GoogleAuthenticator();
}
