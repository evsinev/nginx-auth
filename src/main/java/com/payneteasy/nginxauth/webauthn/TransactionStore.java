package com.payneteasy.nginxauth.webauthn;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Pending ceremonies. At most one pending transaction per browser binding: a new start replaces the old one.
 */
public final class TransactionStore {

    private final int cap;
    private final LongSupplier clock;
    private final ConcurrentHashMap<String, Transaction> transactions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String>      byBinding    = new ConcurrentHashMap<>();

    public TransactionStore(int aCap, LongSupplier aClock) {
        cap = aCap;
        clock = aClock;
    }

    public boolean put(Transaction aTransaction) {
        long now = clock.getAsLong();
        if (transactions.size() >= cap) {
            transactions.values().removeIf(tx -> tx.expiresAt() <= now);
            byBinding.values().removeIf(id -> !transactions.containsKey(id));
            if (transactions.size() >= cap) {
                return false;
            }
        }
        String previous = byBinding.put(aTransaction.binding(), aTransaction.transactionId());
        if (previous != null) {
            transactions.remove(previous);
        }
        transactions.put(aTransaction.transactionId(), aTransaction);
        return true;
    }

    /**
     * Atomically takes the transaction for finish. A transaction of another browser is not consumed;
     * of two concurrent calls at most one gets it.
     */
    public Optional<Transaction> consume(String aTransactionId, String aBinding) {
        if (aTransactionId == null || aBinding == null) {
            return Optional.empty();
        }
        Transaction tx = transactions.get(aTransactionId);
        if (tx == null || !tx.binding().equals(aBinding)) {
            return Optional.empty();
        }
        if (!transactions.remove(aTransactionId, tx)) {
            return Optional.empty();
        }
        byBinding.remove(tx.binding(), tx.transactionId());
        return Optional.of(tx);
    }

    public void cancelForUser(String aUid) {
        transactions.values().removeIf(tx -> tx.uid().equals(aUid));
        byBinding.values().removeIf(id -> !transactions.containsKey(id));
    }

    public void cancelForBinding(String aBinding) {
        String id = byBinding.remove(aBinding);
        if (id != null) {
            transactions.remove(id);
        }
    }

    int size() {
        return transactions.size();
    }
}
