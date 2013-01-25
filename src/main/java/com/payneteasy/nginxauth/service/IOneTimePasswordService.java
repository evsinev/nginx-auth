package com.payneteasy.nginxauth.service;

/**
 *
 */
public interface IOneTimePasswordService {

    boolean checkCode(String aUsername, long aCode);
}
