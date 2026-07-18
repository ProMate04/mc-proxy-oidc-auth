package net.wafflecat.velocityOidcAuth.listener;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.command.CommandExecuteEvent;
import com.velocitypowered.api.event.player.ServerConnectedEvent;
import com.velocitypowered.api.event.player.ServerPostConnectEvent;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.MiniMessage;
import net.wafflecat.velocityOidcAuth.VelocityOidcAuthPlugin;
import net.wafflecat.velocityOidcAuth.cache.AuthSessionCache;
import net.wafflecat.velocityOidcAuth.config.PluginConfig;
import net.wafflecat.velocityOidcAuth.database.SqlDbClient;
import net.wafflecat.velocityOidcAuth.util.DeviceFingerprint;
import org.slf4j.Logger;

import java.util.List;
import java.util.Optional;

/**
 * Keeps every unauthenticated (or wrong-device) player confined to the
 * limbo server:
 * - {@link onServerPreConnect} redirects any attempt to reach a
 *   non-limbo server back to limbo, remembering what they were actually trying to reach
 * - {@link onServerConnected} sends the authentication prompt the moment such a player lands on limbo.
 * If the player is authenticated:
 * - It checks if they have permission to proceed to the backend server
 *
 * Once {@code CallbackHttpServer} validates a login, it moves the player
 * straight out of limbo itself, if they have the right permissions
 *
 */
public final class AuthenticationListener {

    private final ProxyServer proxyServer;
    private final PluginConfig config;
    private final AuthSessionCache sessionCache;
    private final AuthPromptService promptService;
    private final SqlDbClient sqlDbClient;
    private final Logger logger;

    public AuthenticationListener(VelocityOidcAuthPlugin plugin) {
        this.proxyServer = plugin.getProxyServer();
        this.config = plugin.getConfig();
        this.sessionCache = plugin.getSessionCache();
        this.promptService = plugin.getAuthPromptService();
        this.sqlDbClient = plugin.getSqlDbClient();
        this.logger = plugin.getLogger();
    }

    @Subscribe
    public void onServerPreConnect(ServerPreConnectEvent event) {
        logger.debug("EVENT CALL: onServerPreConnect");
        Player player = event.getPlayer();
        RegisteredServer original = event.getOriginalServer();

        //First, save whichever server the player wants to go to
        sessionCache.rememberDesiredServer(player.getUniqueId(), original.getServerInfo().getName());

        // If they are authenticated we don't interfere, they can go anywhere they want
        if(sessionCache.isAuthenticated(player)) {
            logger.info("Player `{}` is already authenticated", player.getUsername());
            if(!player.hasPermission("oidcauth.serverperm." + original.getServerInfo().getName()))
            {
                logger.info("Player '{}' does not have permission to join server '{}', denying", player.getUsername(), original.getServerInfo().getName());
                event.setResult(ServerPreConnectEvent.ServerResult.denied());
                Component message = MiniMessage.miniMessage().deserialize(config.messageNoServerPerm());
                if(event.getPreviousServer() == null)
                {
                    player.disconnect(message);
                } else {
                    player.sendMessage(message);
                }
            }
            return;
        }


        Optional<RegisteredServer> limbo = proxyServer.getServer(config.limboServerName());

        // If the player is not authenticated, we send them to limbo
        event.setResult(ServerPreConnectEvent.ServerResult.allowed(limbo.get()));
    }

    @Subscribe
    public void onServerConnected(ServerPostConnectEvent event) {
        logger.debug("EVENT CALL: onServerConnected");

        Player player = event.getPlayer();
        RegisteredServer server = player.getCurrentServer().get().getServer();

        if (sessionCache.isAuthenticated(player)) {
            sessionCache.refreshAuthenticated(player.getUsername());
            if(event.getPreviousServer() == null) {
                player.sendMessage(MiniMessage.miniMessage().deserialize(config.messageValidSession()));
            }
            logger.info("Connected '{}' to server '{}' ", player.getUsername(), server.getServerInfo().getName());
            return;
        }
        if(sqlDbClient.AddUserToKnownIfNew(player.getUsername(), false)) {
            logger.info("New player `{}`, adding to known players", player.getUsername());
        }
        // If we got here, player is not authenticated: we prompt them for login (basically like /login)
        promptService.promptPlayer(player);
    }


    @Subscribe
    public void onPlayerChat(CommandExecuteEvent event) {
        if (event.getCommandSource() instanceof Player player ) {
            if (!sessionCache.isAuthenticated(player)) {
                List<String> allowedCommands = config.allowedCommandsBeforeAuth();
                if(!allowedCommands.contains(event.getCommand().toLowerCase().split(" ")[0]))
                {
                    player.sendMessage(MiniMessage.miniMessage().deserialize(config.messageCommandChatRestricted()));
                    event.setResult(CommandExecuteEvent.CommandResult.denied());
                }
            }
        }
    }
}
