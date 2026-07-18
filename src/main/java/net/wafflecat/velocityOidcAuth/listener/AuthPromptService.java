package net.wafflecat.velocityOidcAuth.listener;

import com.nimbusds.oauth2.sdk.id.State;
import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.minimessage.MiniMessage;
import net.kyori.adventure.text.minimessage.tag.resolver.Placeholder;
import net.wafflecat.velocityOidcAuth.VelocityOidcAuthPlugin;
import net.wafflecat.velocityOidcAuth.cache.AuthSessionCache;
import net.wafflecat.velocityOidcAuth.cache.PendingAuthorization;
import net.wafflecat.velocityOidcAuth.config.PluginConfig;
import net.wafflecat.velocityOidcAuth.database.SqlDbClient;
import net.wafflecat.velocityOidcAuth.oidc.OidcClient;
import net.wafflecat.velocityOidcAuth.util.DeviceFingerprint;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.event.ClickEvent;
import net.kyori.adventure.text.event.HoverEvent;


import org.slf4j.Logger;

/**
 * OIDC auth: Starts (or restarts) a login flow for a player and sends them the
 * clickable chat message. Used both when a player first lands in limbo and
 * when they run /login to request a fresh link.
 *
 * Password auth: Prompts players with /reg or /login to authenticate using password
 */
public final class AuthPromptService {

    private final PluginConfig config;
    private final OidcClient oidcClient;
    private final AuthSessionCache sessionCache;
    private final SqlDbClient sqlDbClient;
    private final Logger logger;


    public AuthPromptService(VelocityOidcAuthPlugin plugin) {
        this.config = plugin.getConfig();
        this.oidcClient = plugin.getOidcClient();
        this.sessionCache = plugin.getSessionCache();
        this.sqlDbClient = plugin.getSqlDbClient();
        this.logger = plugin.getLogger();
    }

    public void promptPlayer(Player player) {
        String mcUsername = player.getUsername();
        if (sqlDbClient.GetAccountType(mcUsername) == SqlDbClient.accountType.PASSWORD) {
            // if its a password user
            if(sqlDbClient.CheckIfUserIsRegistered(mcUsername)) {
                // if they are registered
                Component message = MiniMessage.miniMessage().deserialize(config.messagePromptPassLogin());
                logger.info("Prompting player '{}' for password login", player.getUsername());
                player.sendMessage(message);
            } else {
                // if they aren't registered
                Component message = MiniMessage.miniMessage().deserialize(config.messagePromptPassReg());
                logger.info("Prompting player '{}' for password registration", player.getUsername());
                player.sendMessage(message);
            }
        } else if(sqlDbClient.GetAccountType(mcUsername) == SqlDbClient.accountType.OIDC) {
            // otherwise its an OIDC user
            try {
                State state = new State();
                OidcClient.AuthorizationRequestResult authRequest = oidcClient.buildAuthorizationRequest(state);

                String fingerprint = DeviceFingerprint.compute(player);
                sessionCache.putPending(new PendingAuthorization(
                        state.getValue(),
                        authRequest.codeVerifier().getValue(),
                        mcUsername,
                        player.getUniqueId(),
                        fingerprint));

                String url =  authRequest.authorizationUri().toString();

                Component message = MiniMessage.miniMessage().deserialize(config.messageOIDCPrompt(),
                        Placeholder.styling("login_url_click",
                                ClickEvent.openUrl(url),
                                HoverEvent.showText(MiniMessage.miniMessage().deserialize(config.messageLinkHover()))));

                logger.info("Prompting player '{}' for OIDC authentication", player.getUsername());
                player.sendMessage(message);
            } catch (Exception e) {
                logger.warn("Failed to build an OIDC authorization request for {}", mcUsername, e);
                Component message = MiniMessage.miniMessage().deserialize(config.messageOIDCPrompt(), Placeholder.component("reason", Component.text("Could not reach the authentication provider")));
                player.sendMessage(message);
            }
        }

    }
}
