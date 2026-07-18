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
import net.wafflecat.velocityOidcAuth.util.DeviceFingerprint;
import org.slf4j.Logger;

import java.util.Optional;

/**
 * Command for password auth players to register an account
 */

public class RegisterCommand implements SimpleCommand {

    private final PluginConfig config;
    private final Logger logger;
    private final AuthSessionCache sessionCache;
    private final SqlDbClient sqlDbClient;
    private final ProxyServer proxyServer;

    public RegisterCommand(VelocityOidcAuthPlugin plugin) {
        this.config = plugin.getConfig();
        this.logger = plugin.getLogger();
        this.sessionCache = plugin.getSessionCache();
        this.sqlDbClient = plugin.getSqlDbClient();
        this.proxyServer = plugin.getProxyServer();
    }

    @Override
    public void execute(final Invocation invocation) {
        if (!(invocation.source() instanceof Player player)) {
            invocation.source().sendMessage(MiniMessage.miniMessage().deserialize(config.messageCommandPlayerOnly()));
            return;
        }
        String fingerprint = DeviceFingerprint.compute(player);
        String mcUsername = player.getUsername();

        if (sqlDbClient.CheckIfUserIsRegistered(mcUsername)) {
            player.sendMessage(MiniMessage.miniMessage().deserialize(config.messageAlreadyRegistered()));
            return;
        }

        String[] args = invocation.arguments();
        if(args.length != 2) {
            player.sendMessage(MiniMessage.miniMessage().deserialize(config.messageCommandIncorrect()));
            return;
        }

        if(!args[0].equals(args[1])) {
            player.sendMessage(MiniMessage.miniMessage().deserialize(config.messagePassRegMismatch()));
            return;
        }

        sqlDbClient.RegisterPasswordUser(mcUsername, args[0]);

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
        player.sendMessage(MiniMessage.miniMessage().deserialize(config.messagePassRegSuccess()));
        logger.info("Registered - Password | Minecraft username: {}", player.getUsername());
    }

    @Override
    public boolean hasPermission(final Invocation invocation) {
        Player player = (Player) invocation.source();
        return sqlDbClient.GetAccountType(player.getUsername()) == SqlDbClient.accountType.PASSWORD;
    }
}

