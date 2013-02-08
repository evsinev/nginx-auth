package com.payneteasy.nginxauth.service.impl;

import com.payneteasy.nginxauth.service.INonceManager;

import java.util.*;

/**
 */
public class NonceManagerImpl implements INonceManager {

    private final static NonceManagerImpl INSTANCE = new NonceManagerImpl();

    public static INonceManager getInstance() {
        return INSTANCE;
    }

    private NonceManagerImpl() {
    }

    @Override
    public synchronized String addNonce() {
        String key = UUID.randomUUID().toString();
        theList.add(key);

        while(theList.size()>100) {
            theList.remove(0);
        }

        return key;
    }

    @Override
    public synchronized boolean checkNonce(String aNonce) {
        for(int i=0; i<theList.size(); i++) {
            if(theList.get(i).equals(aNonce)) {
                theList.remove(i);
                return true;
            }
        }
        return false;
    }

    private final List<String> theList = new ArrayList<String>(100);

}
