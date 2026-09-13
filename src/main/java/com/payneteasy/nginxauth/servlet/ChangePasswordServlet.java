package com.payneteasy.nginxauth.servlet;

import com.payneteasy.nginxauth.service.ChangePasswordException;
import com.payneteasy.nginxauth.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.AuthenticationException;
import jakarta.servlet.http.HttpServletRequest;

public class ChangePasswordServlet extends LoginFormServlet {

    private static final Logger LOG = LoggerFactory.getLogger(ChangePasswordServlet.class);

    @Override
    public void doCustomAction(String aUsername, String aCurrentPassword, HttpServletRequest aRequest) throws ChangePasswordException {

        String password_1 = aRequest.getParameter("j_password_new_1");
        String password_2 = aRequest.getParameter("j_password_new_2");

        if (tooLong(password_1, MAX_PASSWORD) || tooLong(password_2, MAX_PASSWORD)) {
            throw new ChangePasswordException("New password is too long");
        }

        if (StringUtils.isEmpty(password_1) || StringUtils.isEmpty(password_2)) {
            throw new ChangePasswordException("New password is empty");
        }

        if(!password_1.equals(password_2)) {
            throw new ChangePasswordException("New passwords do not match");
        }

        try {
            theAuthService.changePassword(aUsername, aCurrentPassword, password_1);
        } catch (AuthenticationException e) {
            LOG.error("Could not change password", e);
            throw new ChangePasswordException("Could not change password");
        }

    }

    public boolean canCheckAccess() {
        return false;
    }

}
