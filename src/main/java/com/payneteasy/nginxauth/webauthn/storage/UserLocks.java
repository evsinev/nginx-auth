package com.payneteasy.nginxauth.webauthn.storage;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Per-user locks shared by the credential repository, sessions and transactions.
 * The key set is bounded by users that passed LDAP authentication or were named by an administrator.
 */
public final class UserLocks {

    public interface Action<T, E extends Exception> {
        T run() throws E;
    }

    private final ConcurrentHashMap<String, ReentrantLock> locks = new ConcurrentHashMap<>();

    public <T, E extends Exception> T withLock(String aUid, Action<T, E> aAction) throws E {
        ReentrantLock lock = locks.computeIfAbsent(aUid, uid -> new ReentrantLock());
        lock.lock();
        try {
            return aAction.run();
        } finally {
            lock.unlock();
        }
    }

    public boolean isHeldByCurrentThread(String aUid) {
        ReentrantLock lock = locks.get(aUid);
        return lock != null && lock.isHeldByCurrentThread();
    }
}
