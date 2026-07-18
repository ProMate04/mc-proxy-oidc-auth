package net.wafflecat.velocityOidcAuth.cache;

import java.util.UUID;

/**
 * Tracks a login flow that has been started for a specific player but not yet
 * completed. Keyed by the OAuth2 "state" parameter so the callback can look
 * it back up (and so we can reject callbacks with an unknown/forged state).
 */
public final class PendingAuthorization {

    private final String state;
    private final String codeVerifier;
    private final String minecraftUsername;
    private final UUID minecraftUuid;
    private final String deviceFingerprint;
    private final long createdAtEpochMillis;

    public PendingAuthorization(String state, String codeVerifier, String minecraftUsername, UUID minecraftUuid,
                                 String deviceFingerprint) {
        this.state = state;
        this.codeVerifier = codeVerifier;
        this.minecraftUsername = minecraftUsername;
        this.minecraftUuid = minecraftUuid;
        this.deviceFingerprint = deviceFingerprint;
        this.createdAtEpochMillis = System.currentTimeMillis();
    }

    public String state() {
        return state;
    }

    public String codeVerifier() {
        return codeVerifier;
    }

    public String minecraftUsername() {
        return minecraftUsername;
    }

    public UUID minecraftUuid() {
        return minecraftUuid;
    }

    public String deviceFingerprint() {
        return deviceFingerprint;
    }

    public long createdAtEpochMillis() {
        return createdAtEpochMillis;
    }
}
