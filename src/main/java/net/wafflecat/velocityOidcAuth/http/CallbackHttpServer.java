package net.wafflecat.velocityOidcAuth.http;

import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.tag.resolver.Placeholder;
import net.wafflecat.velocityOidcAuth.VelocityOidcAuthPlugin;
import net.wafflecat.velocityOidcAuth.cache.AuthSessionCache;
import net.wafflecat.velocityOidcAuth.cache.PendingAuthorization;
import net.wafflecat.velocityOidcAuth.config.PluginConfig;
import net.wafflecat.velocityOidcAuth.database.SqlDbClient;
import net.wafflecat.velocityOidcAuth.ldap.LdapClient;
import net.wafflecat.velocityOidcAuth.luckperms.LuckPermsHelper;
import net.wafflecat.velocityOidcAuth.oidc.OidcClient;
import net.kyori.adventure.text.minimessage.MiniMessage;
import org.slf4j.Logger;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

/**
 * Minimal HTTP server (JDK built-in, no extra dependency) that handles the
 * OAuth2 authorization code redirect. Put a reverse proxy with TLS in front
 * of this in production - browsers and some providers require HTTPS
 * redirect URIs.
 *
 * On a successful, matching login this pulls the player straight out of
 * limbo into their destination server
 */

public final class CallbackHttpServer {

    private final PluginConfig config;
    private final OidcClient oidcClient;
    private final SqlDbClient sqlDbClient;
    private final AuthSessionCache sessionCache;
    private final ProxyServer proxyServer;
    private final LdapClient ldapClient;
    private final LuckPermsHelper luckPermsHelper;
    private final Logger logger;
    private HttpServer server;

    public CallbackHttpServer(VelocityOidcAuthPlugin plugin ) {
        this.config = plugin.getConfig();
        this.oidcClient = plugin.getOidcClient();
        this.sqlDbClient = plugin.getSqlDbClient();
        this.sessionCache = plugin.getSessionCache();
        this.proxyServer = plugin.getProxyServer();
        this.ldapClient = plugin.getLdapClient();
        this.luckPermsHelper = plugin.getLuckPermsHelper();
        this.logger = plugin.getLogger();
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(config.callbackBindAddress(), config.callbackBindPort()), 0);
        server.createContext(config.callbackPath(), new CallbackHandler());
        server.setExecutor(Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "velocity-oidc-auth-http");
            t.setDaemon(true);
            return t;
        }));
        server.start();
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    private final class CallbackHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                Map<String, String> params = queryParams(exchange.getRequestURI());
                String state = params.get("state");
                String code = params.get("code");
                String errorParam = params.get("error");

                if (state == null) {
                    respond(exchange, 400, page("Invalid request", "Missing 'state' parameter.", false));
                    return;
                }

                PendingAuthorization pending = sessionCache.takePending(state);
                if (pending == null) {
                    respond(exchange, 400, page("Login link expired",
                            "This link has expired or was already used. Go back to Minecraft and run "
                                    + "<b>/login</b> to get a new one.", false));
                    logger.info("Login failed! - Login link expired");
                    return;
                }

                if (errorParam != null) {
                    String description = params.getOrDefault("error_description", errorParam);
                    notifyError(pending, description);
                    respond(exchange, 200, page("Authentication failed", escape(description), false));
                    return;
                }

                if (code == null) {
                    respond(exchange, 400, page("Invalid request", "Missing 'code' parameter.", false));
                    return;
                }

                IDTokenClaimsSet claims = oidcClient.exchangeAndValidate(code, pending.codeVerifier());
                String identityUsername = claims.getStringClaim(oidcClient.usernameClaim());
                String mcUsername = pending.minecraftUsername();
                String identityUUID =  claims.getStringClaim(oidcClient.UUIDClaim());
                Optional<Player> optPlayer = proxyServer.getPlayer(mcUsername);

                if (identityUUID == null) {
                    notifyError(pending, "provider did not return a '" + oidcClient.UUIDClaim() + "' claim");
                    respond(exchange, 200, page("Authentication failed",
                            "The identity provider did not return the expected UUID claim ('"
                                    + escape(oidcClient.UUIDClaim()) + "').", false));
                    logger.error("OIDC provider didn't return the expected UUID claim!!");
                    // Ask your admin to check the OIDC scopes/claims.
                    return;
                }

                if(sqlDbClient.CheckIfUserIsRegistered(mcUsername))
                {
                    if(sqlDbClient.CheckIfOIDCAccMatches(mcUsername, identityUUID))
                    {
                        sessionCache.markAuthenticated(mcUsername, pending.deviceFingerprint());
                        notifySuccessAndConnect(pending, identityUsername);

                        respond(exchange, 200, page("Logged in!",
                                "Logged in as <b>" + escape(identityUsername) + "</b>. You can close this tab - "
                                        + "you'll be moved into the server automatically.", true));
                        logger.info("Logged in - {}: {} | Minecraft username: {}", config.providerName(), identityUsername, mcUsername);
                    } else {
                        // didn't match -> not correct OIDC account
                        notifyMismatch(pending, identityUsername);
                        respond(exchange, 200, page("Wrong " + config.providerName(),
                                "You authenticated as <b>" + escape(identityUsername) + "</b>, but this Minecraft user is registered to a different " + config.providerName() + ". Go back to Minecraft, "
                                        + "run <b>/login</b> again and try signing into a different " + config.providerName() + ", or check your Minecraft username", false));
                        logger.info("Login failed - Account mismatch! - {}: {} | Minecraft username: {}", config.providerName(), identityUsername, mcUsername);
                    }

                } else {
                    sessionCache.markAuthenticated(mcUsername, pending.deviceFingerprint());
                    sqlDbClient.RegisterOIDCUser(mcUsername, identityUUID, identityUsername);
                    notifySuccessAndConnect(pending, identityUsername);

                    respond(exchange, 200, page("Registered User!",
                            "Registered <b>" + escape(mcUsername) + "</b> to " + config.providerName() + " <b>" + escape(identityUsername) + "</b>. You can close this tab - "
                                    + "you'll be moved into the server automatically.", true));
                    logger.info("Registered - {}: {} | Minecraft username: {}", config.providerName(), identityUsername, mcUsername);
                }

                return;
            } catch (Exception e) {
                logger.warn("Error handling OIDC callback", e);
                try {
                    respond(exchange, 500, page("Something went wrong", "Internal error", false));
                } catch (IOException ignored) {
                    // exchange already broken; nothing more we can do
                }
            } finally {
                exchange.close();
            }
        }
    }

    private void notifySuccessAndConnect(PendingAuthorization pending, String OIDCUsername) {
        Optional<Player> playerOpt = proxyServer.getPlayer(pending.minecraftUuid());
        if(config.LDAPEnabled())
        {
            ldapClient.syncUserLdap(luckPermsHelper, OIDCUsername, pending.minecraftUsername());
        }
        if (playerOpt.isEmpty()) {
            // It is possible the player left while completing the auth flow
            // This is not a problem, since the session cache is already saved and will let them through next time they join
            return;
        }
        Player player = playerOpt.get();
        player.sendMessage(MiniMessage.miniMessage().deserialize(config.messageAuthSuccess()));

        String desiredServerName = sessionCache.getDesiredServer(pending.minecraftUuid());
        String targetName = desiredServerName != null ? desiredServerName : config.fallbackTargetServerName();

        Optional<RegisteredServer> target = proxyServer.getServer(targetName);

        player.createConnectionRequest(target.get()).connect().whenComplete((result, throwable) -> {
            if (throwable != null) {
                logger.warn("Failed to connect {} to {} after authentication", player.getUsername(), targetName, throwable);
            } else if (!result.isSuccessful()) {
                logger.warn("Connecting {} to {} after authentication was not successful: {}",
                        player.getUsername(), targetName, result.getReasonComponent().orElse(null));
            }
        });
    }

    private void notifyMismatch(PendingAuthorization pending, String identityUsername) {
        Component message = MiniMessage.miniMessage().deserialize(config.messageUserMismatch(), Placeholder.component("identity", Component.text(identityUsername)), Placeholder.component("username", Component.text(pending.minecraftUsername())));
        proxyServer.getPlayer(pending.minecraftUuid()).ifPresent(player -> player.sendMessage(message));
    }

    private void notifyError(PendingAuthorization pending, String reason) {
        Component message = MiniMessage.miniMessage().deserialize(config.messageAuthError(), Placeholder.component("reason", Component.text(reason)));
        proxyServer.getPlayer(pending.minecraftUuid()).ifPresent(player -> player.sendMessage(message));
    }

    private static String fill(String template, String... kvPairs) {
        String result = template;
        for (int i = 0; i + 1 < kvPairs.length; i += 2) {
            result = result.replace("{" + kvPairs[i] + "}", kvPairs[i + 1]);
        }
        return result;
    }

    private static Map<String, String> queryParams(URI uri) {
        String query = uri.getRawQuery();
        if (query == null || query.isBlank()) {
            return Map.of();
        }
        return java.util.Arrays.stream(query.split("&"))
                .map(pair -> pair.split("=", 2))
                .collect(Collectors.toMap(
                        p -> urlDecode(p[0]),
                        p -> p.length > 1 ? urlDecode(p[1]) : "",
                        (a, b) -> a));
    }

    private static String urlDecode(String s) {
        return java.net.URLDecoder.decode(s, StandardCharsets.UTF_8);
    }

    private static String escape(String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static String page(String title, String bodyHtml, boolean success) {
        String color = success ? "#2e7d32" : "#b71c1c";
        return "<!doctype html><html><head><meta charset='utf-8'>"
                + "<title>" + escape(title) + "</title>"
                + "<meta name='viewport' content='width=device-width, initial-scale=1'>"
                + "<style>body{font-family:system-ui,sans-serif;background:#111;color:#eee;"
                + "display:flex;align-items:center;justify-content:center;height:100vh;margin:0}"
                + ".card{max-width:480px;padding:2rem;text-align:center}"
                + "h1{color:" + color + "}</style></head><body><div class='card'>"
                + "<h1>" + escape(title) + "</h1><p>" + bodyHtml + "</p></div></body></html>";
    }

    private static void respond(HttpExchange exchange, int status, String html) throws IOException {
        byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
