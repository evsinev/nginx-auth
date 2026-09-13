package com.payneteasy.nginxauth.servlet.api;

import com.google.gson.Gson;
import com.payneteasy.nginxauth.service.IOneTimePasswordService;
import com.payneteasy.nginxauth.service.impl.RateLimiter;
import com.payneteasy.nginxauth.servlet.api.messages.CheckUsernameOtpRequest;
import com.payneteasy.nginxauth.util.HttpRequestUtil;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.Set;

import static com.payneteasy.nginxauth.util.StringUtils.isEmpty;

public class ApiCheckUsernameOtpServlet extends HttpServlet {

    private final IOneTimePasswordService oneTimePasswordService;
    private final Gson                    gson;
    private final Set<String>             accessTokens;

    public ApiCheckUsernameOtpServlet(IOneTimePasswordService oneTimePasswordService, Gson gson, Set<String> accessTokens) {
        this.oneTimePasswordService = oneTimePasswordService;
        this.gson                   = gson;
        this.accessTokens           = accessTokens;
    }

    @Override
    protected void doPost(HttpServletRequest aRequest, HttpServletResponse aResponse) throws IOException {
        ApiContext api = new ApiContext(aRequest, aResponse, gson, accessTokens);

        Optional<String> errorOpt = api.checkAccessToken();
        if (errorOpt.isPresent()) {
            api.writeError(401, errorOpt.get());
            return;
        }

        CheckUsernameOtpRequest checkRequest = api.fromJson(CheckUsernameOtpRequest.class);

        if (isEmpty(checkRequest.getUsername())) {
            api.writeError(400, "Field username is empty");
            return;
        }

        if (isEmpty(checkRequest.getOtp())) {
            api.writeError(400, "Field otp is empty");
            return;
        }

        long otp;
        try {
            otp = Long.parseLong(checkRequest.getOtp());
        } catch (NumberFormatException e) {
            api.writeError(400, "OTP code is not a number");
            return;
        }

        String username = checkRequest.getUsername();
        String ip = HttpRequestUtil.clientIp(aRequest);
        String ipKey = ip == null ? null : RateLimiter.ipKey(ip);
        RateLimiter rateLimiter = RateLimiter.getInstance();
        if (rateLimiter.isBlocked(RateLimiter.userKey(username))
                || rateLimiter.isBlocked(ipKey)) {
            api.writeError(401, "Bad OTP code");
            return;
        }

        if (!oneTimePasswordService.checkCode(username, otp)) {
            rateLimiter.recordFailure(RateLimiter.userKey(username));
            rateLimiter.recordFailure(ipKey);
            api.writeError(401, "Bad OTP code");
            return;
        }

        rateLimiter.recordSuccess(RateLimiter.userKey(username));
        api.writeSuccessResponse(username);
    }
}
