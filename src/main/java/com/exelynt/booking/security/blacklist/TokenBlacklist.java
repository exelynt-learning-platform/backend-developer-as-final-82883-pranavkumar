package com.exelynt.booking.security.blacklist;

import java.time.Instant;

/**
 * Store of access-token ids revoked before their natural expiry.
 *
 * <p>Backed by Redis, so a logout is honoured by every instance and not only
 * by the one that served it. The interface remains so the filter and the auth
 * service depend on the behaviour rather than on Redis itself.</p>
 *
 * <p>Implementations fail closed: a backend error must propagate rather than
 * treating an unavailable blacklist as empty, because admitting a request
 * while revocation state cannot be read is unsafe.</p>
 */
public interface TokenBlacklist {

    /** Blocks {@code jti} until {@code expiresAt}; entries past that point may be dropped. */
    void blacklist(String jti, Instant expiresAt);

    /** Returns whether {@code jti} is revoked; backend failures are not treated as a miss. */
    boolean isBlacklisted(String jti);
}
