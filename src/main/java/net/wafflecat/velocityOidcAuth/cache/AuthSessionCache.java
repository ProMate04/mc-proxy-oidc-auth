package net.wafflecat.velocityOidcAuth.cache;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.player.CookieReceiveEvent;
import com.velocitypowered.api.event.player.PlayerSettingsChangedEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import net.kyori.adventure.key.Key;
import net.wafflecat.velocityOidcAuth.VelocityOidcAuthPlugin;
import net.wafflecat.velocityOidcAuth.config.PluginConfig;
import net.wafflecat.velocityOidcAuth.util.DeviceFingerprint;
import org.slf4j.Logger;

import javax.swing.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.*;

/**
 * In-memory cache for saving pending authentications and sessions
 */
public final class AuthSessionCache {

    private final Cache<String, PendingAuthorization> pendingByState;
    private final Cache<String, String> authenticatedUsernames;
    private final Cache<UUID, String> desiredServerByUuid;
    private final SecureRandom random;
    private final Key tokenKey = Key.key("oidcauth", "session_token");
    private final Map<String, CompletableFuture<byte[]>> cookieRequests = new ConcurrentHashMap<>();
    private final Logger logger;
    private final ProxyServer proxyServer;

    public AuthSessionCache(VelocityOidcAuthPlugin plugin) {
        PluginConfig config = plugin.getConfig();
        this.logger = plugin.getLogger();
        this.proxyServer = plugin.getProxyServer();
        this.pendingByState = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofMinutes(config.pendingAuthTimeoutMinutes()))
                .maximumSize(10_000)
                .build();

        this.authenticatedUsernames = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofMinutes(config.sessionDurationMinutes()))
                .maximumSize(10_000)
                .build();

        // Remembers which server a player was actually trying to reach while
        // they sit in limbo, so we can send them there (rather than a fixed
        // fallback) once they authenticate. Kept a bit longer than the
        // pending-auth timeout
        this.desiredServerByUuid = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofMinutes(Math.max(30, config.pendingAuthTimeoutMinutes() * 2)))
                .maximumSize(10_000)
                .build();
        this.random = new SecureRandom();
    }

    public void putPending(PendingAuthorization pending) {
        pendingByState.put(pending.state(), pending);
    }

    public PendingAuthorization takePending(String state) {
        PendingAuthorization pending = pendingByState.getIfPresent(state);
        if (pending != null) {
            pendingByState.invalidate(state);
        }
        return pending;
    }

    // Marks a username as authenticated, tying the session to the given device fingerprint.
    public void markAuthenticated(String mcUsername, String deviceFingerprint) {
        String newToken = generateToken();
        String fullFingerprint = deviceFingerprint + ";" + newToken;
        authenticatedUsernames.put(mcUsername, fullFingerprint);
        if (proxyServer.getPlayer(mcUsername).isPresent()) {
            proxyServer.getPlayer(mcUsername).get().storeCookie(tokenKey, newToken.getBytes(StandardCharsets.UTF_8));
        }
    }

    public void refreshAuthenticated(String mcUsername)
    {
        String fingerprint = authenticatedUsernames.getIfPresent(mcUsername);
        if(fingerprint != null) {
            authenticatedUsernames.put(mcUsername, fingerprint);
        }
    }

    // True only if this username is authenticated AND it was the same device that authenticated it.
    public boolean isAuthenticated(Player player) {
        // first check if anything is even stored
        String storedFullFingerprint = authenticatedUsernames.getIfPresent(player.getUsername());
        if (storedFullFingerprint == null) { return false; }
        logger.info("Authentication check:");
        // primary check is the cookie token, it can only exist if the player has already
        // authenticated since they logged on
        if(CheckPlayerToken(player, storedFullFingerprint)) {
            return true;
        }

        // if that does not exist, then the player could have rejoined
        // (the cookies only get stored while they are connected to the network)
        // and since we have them in session storage, we can check if the
        // device fingerprint matches
        if(CheckPlayerDeviceFingerprint(player, storedFullFingerprint)) {
            // we also send them the token
            String storedToken = storedFullFingerprint.split(";")[1];
            player.storeCookie(tokenKey, storedToken.getBytes(StandardCharsets.UTF_8));
            return true;
        }

        // if neither of them matched then the player is surely not authenticated
        return false;
    }

    public boolean CheckPlayerToken(Player player, String storedFullFingerprint) {
        String storedToken = storedFullFingerprint.split(";")[1];
        boolean[] clientHasToken = {false};
        try {
            getCookieAsync(player).thenAccept(clientToken -> {
                if (clientToken == null) { return; }
                logger.info("  | STORED token: {}", storedToken);
                logger.info("  | CLIENT token: {}", new String(clientToken, StandardCharsets.UTF_8));
                clientHasToken[0] = clientToken != null && storedToken.equals(new String(clientToken, StandardCharsets.UTF_8));
            }).join();
        } catch (CompletionException e){
            logger.warn("Getting cookie from player timed out!");
            return false;
        }

        if(clientHasToken[0]) {
            // if cookie matches they are for sure authenticatedbohóc
            logger.info("  | Authentication valid by cookie.");
            return true;
        }
        return false;
    }

    public boolean CheckPlayerDeviceFingerprint(Player player, String storedFullFingerprint) {
        String storedDeviceFingerprint = storedFullFingerprint.split(";")[0];
        String deviceFingerprint = DeviceFingerprint.compute(player);
        logger.info("  | STORED fingerprint: {}", storedDeviceFingerprint);
        logger.info("  | CLIENT fingerprint: {}", deviceFingerprint);
        if(storedDeviceFingerprint.equals(deviceFingerprint))
        {
            // if cookie didn't match but device fingerprint did, we send them the cookie
            logger.info("  | Authentication valid by device fingerprint (fallback after cookie).");
            return true;
        }
        return false;
    }

    public CompletableFuture<byte[]> getCookieAsync(Player player) {
        CompletableFuture<byte[]> futureToken = new CompletableFuture<>();
        cookieRequests.put(player.getUsername(), futureToken);
        player.requestCookie(tokenKey);
        futureToken.orTimeout(2, TimeUnit.SECONDS)
                .whenComplete( (result, exception) -> {
                    cookieRequests.remove(player.getUsername());
                });
        return futureToken;
    }

    @Subscribe
    public void onPlayerSettingsChange(PlayerSettingsChangedEvent event)
    {
        String mcUsername = event.getPlayer().getUsername();
        String storedFullFingerprint = authenticatedUsernames.getIfPresent(mcUsername);
        if (storedFullFingerprint == null) { return; }
        if(CheckPlayerToken(event.getPlayer(), storedFullFingerprint)) {
            String storedToken = storedFullFingerprint.split(";")[1];
            String newDeviceFingerprint = DeviceFingerprint.compute(event.getPlayer());
            String fullFingerprint = newDeviceFingerprint + ";" + storedToken;
            authenticatedUsernames.put(mcUsername, fullFingerprint);
            event.getPlayer().storeCookie(tokenKey, storedToken.getBytes(StandardCharsets.UTF_8));
        }
    }

    @Subscribe
    public void onCookieReceive(CookieReceiveEvent event)
    {
        if (!event.getOriginalKey().equals(tokenKey)) {
            return;
        }
        event.setResult(CookieReceiveEvent.ForwardResult.handled());

        String mcUsername = event.getPlayer().getUsername();
        CompletableFuture<byte[]> future = cookieRequests.remove(mcUsername);
        if (future != null) {
            future.complete(event.getOriginalData());
        }

    }


    public void invalidateSession(String username) {
        authenticatedUsernames.invalidate(username);
    }

    public void rememberDesiredServer(UUID playerUuid, String serverName) {
        desiredServerByUuid.put(playerUuid, serverName);
    }

    public String getDesiredServer(UUID playerUuid) {
        return desiredServerByUuid.getIfPresent(playerUuid);
    }


    public String generateToken()
    {
        return DeviceFingerprint.sha256Hex(Integer.toString(random.nextInt()));
    }
}
