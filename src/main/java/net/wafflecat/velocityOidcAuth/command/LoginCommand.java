package net.wafflecat.velocityOidcAuth.command;

import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.kyori.adventure.text.minimessage.MiniMessage;
import net.wafflecat.velocityOidcAuth.VelocityOidcAuthPlugin;
import net.wafflecat.velocityOidcAuth.cache.AuthSessionCache;
import net.wafflecat.velocityOidcAuth.config.PluginConfig;
import net.wafflecat.velocityOidcAuth.database.SqlDbClient;
import net.wafflecat.velocityOidcAuth.listener.AuthPromptService;
import net.wafflecat.velocityOidcAuth.util.DeviceFingerprint;
import org.slf4j.Logger;

import java.util.Optional;

/**
 * OIDC auth: Lets a player re-request the authentication link without having to
 * reconnect - handy if the original link expired.
 *
 * Password auth: Lets the player to log in
 */
public final class LoginCommand implements SimpleCommand {

    private final PluginConfig config;
    private final Logger logger;
    private final AuthSessionCache sessionCache;
    private final AuthPromptService promptService;
    private final SqlDbClient sqlDbClient;
    private final ProxyServer proxyServer;

    public LoginCommand(VelocityOidcAuthPlugin plugin) {
        this.config = plugin.getConfig();
        this.logger = plugin.getLogger();
        this.sessionCache = plugin.getSessionCache();
        this.promptService = plugin.getAuthPromptService();
        this.sqlDbClient = plugin.getSqlDbClient();
        this.proxyServer = plugin.getProxyServer();
    }

    @Override
    public void execute(Invocation invocation) {
        if (!(invocation.source() instanceof Player player)) {
            invocation.source().sendMessage(MiniMessage.miniMessage().deserialize(config.messageCommandPlayerOnly()));
            return;
        }

        String fingerprint = DeviceFingerprint.compute(player);
        String mcUsername = player.getUsername();
        if (sessionCache.isAuthenticated(player)) {
            player.sendMessage(MiniMessage.miniMessage().deserialize(config.messageAlreadyAuthenticated()));
            return;
        }

        if (sqlDbClient.GetAccountType(mcUsername) == SqlDbClient.accountType.PASSWORD
                && !sqlDbClient.CheckIfUserIsRegistered(mcUsername)) {
            player.sendMessage(MiniMessage.miniMessage().deserialize(config.messagePromptPassReg()));
            return;
        }

        String[] args = invocation.arguments();
        if(sqlDbClient.GetAccountType(mcUsername) == SqlDbClient.accountType.PASSWORD)
        {
            if(args.length != 1) {
                player.sendMessage(MiniMessage.miniMessage().deserialize(config.messageCommandIncorrect()));
                return;
            }

            if(sqlDbClient.CheckIfPassMatches(mcUsername, args[0]))
            {
                // password auth passed
                sessionCache.markAuthenticated(mcUsername, fingerprint);
                String desiredServerName = sessionCache.getDesiredServer(player.getUniqueId());
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
                player.sendMessage(MiniMessage.miniMessage().deserialize(config.messageAuthSuccess()));
                logger.info("Logged in - Password | Minecraft account {}", player.getUsername());
            } else {
                player.sendMessage(MiniMessage.miniMessage().deserialize(config.messagePassLoginMismatch()));
                logger.info("Login failed - Password | Minecraft account {}", player.getUsername());
            }
            return;
        }

        promptService.promptPlayer(player);
    }
}
