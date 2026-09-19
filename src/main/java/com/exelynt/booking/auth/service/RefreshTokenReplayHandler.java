package com.exelynt.booking.auth.service;

import com.exelynt.booking.audit.common.AuditAction;
import com.exelynt.booking.audit.service.AuditService;
import com.exelynt.booking.auth.token.RefreshTokenStore;
import com.exelynt.booking.auth.token.dto.StoredRefreshToken;
import com.exelynt.booking.common.exception.type.UnauthorizedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RefreshTokenReplayHandler {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenReplayHandler.class);
    private static final String ENTITY_TYPE = "User";
    private static final String INVALID_REFRESH_TOKEN = "Refresh token is invalid, expired or already used";

    private final RefreshTokenStore refreshTokenStore;
    private final AuditService auditService;

    public RefreshTokenReplayHandler(RefreshTokenStore refreshTokenStore, AuditService auditService) {
        this.refreshTokenStore = refreshTokenStore;
        this.auditService = auditService;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW, noRollbackFor = UnauthorizedException.class)
    public void handle(StoredRefreshToken token) {
        int revoked = refreshTokenStore.revokeAllForUser(token.userId());
        auditService.record(token.username(), AuditAction.REFRESH_TOKEN_REUSE_DETECTED,
                ENTITY_TYPE, token.userId());
        log.warn("refresh_token_reuse_detected username={} revokedTokens={} - "
                + "all sessions for this user have been ended", token.username(), revoked);
        throw new UnauthorizedException(INVALID_REFRESH_TOKEN);
    }
}
