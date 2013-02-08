package com.payneteasy.nginxauth.service;

public interface INonceManager {

    String addNonce();

    boolean checkNonce(String aNonce);
}
