package net.wafflecat.velocityOidcAuth.command;


import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.MiniMessage;
import net.kyori.adventure.text.minimessage.tag.resolver.Placeholder;
import net.wafflecat.velocityOidcAuth.VelocityOidcAuthPlugin;
import net.wafflecat.velocityOidcAuth.cache.AuthSessionCache;
import net.wafflecat.velocityOidcAuth.config.PluginConfig;
import net.wafflecat.velocityOidcAuth.database.SqlDbClient;
import net.wafflecat.velocityOidcAuth.luckperms.LuckPermsHelper;
import org.slf4j.Logger;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * Commands (for admins) to manage players, including unregistering and changing account type
 */

public final class AuthCommand implements SimpleCommand {

    private final SqlDbClient sqlDbClient;
    private final ProxyServer proxyServer;
    private final AuthSessionCache sessionCache;
    private final LuckPermsHelper luckPermsHelper;
    private final Logger logger;
    private final PluginConfig config;

    public AuthCommand(VelocityOidcAuthPlugin plugin) {
        this.sqlDbClient = plugin.getSqlDbClient();
        this.proxyServer = plugin.getProxyServer();
        this.sessionCache = plugin.getSessionCache();
        this.luckPermsHelper = plugin.getLuckPermsHelper();
        this.logger = plugin.getLogger();
        this.config = plugin.getConfig();
    }

    @Override
    public void execute(final Invocation invocation) {
        CommandSource source = invocation.source();
        String[] args = invocation.arguments();

        if(args.length < 2) {
            source.sendMessage(MiniMessage.miniMessage().deserialize(config.messageCommandIncorrect()));
            return;
        }

        String mcUsername = args[0];
        String action = args[1];

        if(proxyServer.getPlayer(mcUsername).isPresent()) {
            // if the player is online, we invalidate the session and send the given player to lobby
            Player targetPlayer = proxyServer.getPlayer(mcUsername).get();
            sessionCache.invalidateSession(mcUsername);
            Optional<RegisteredServer> limboServer = proxyServer.getServer(config.limboServerName());
            targetPlayer.createConnectionRequest(limboServer.get()).connect();
            targetPlayer.sendMessage(MiniMessage.miniMessage().deserialize(config.messageLoggedOut()));
            //source.sendMessage(MiniMessage.miniMessage().deserialize("<red>Player sent to the lobby lmfaooooo"));
        }

        if(action.equalsIgnoreCase("unregister")) {
            if (sqlDbClient.GetAccountType(mcUsername) != SqlDbClient.accountType.NONE
                    && sqlDbClient.CheckIfUserIsRegistered(mcUsername))
            {
                if(sqlDbClient.UnregisterUser(mcUsername)) {
                    source.sendMessage(MiniMessage.miniMessage().deserialize(config.messageAccountUnregistered()));
                    luckPermsHelper.removeAllAccessFromPlayer(mcUsername);
                    logger.info("Player '{}' has been successfully unregistered", mcUsername);
                }
            } else {
                source.sendMessage(MiniMessage.miniMessage().deserialize(config.messageAccountNotRegistered()));
            }
            return;
        } else if(action.equalsIgnoreCase("setAccountType")) {
            String desiredAccType = args[2];
            if(desiredAccType.equalsIgnoreCase("password")) {
                if(sqlDbClient.GetAccountType(mcUsername) == SqlDbClient.accountType.PASSWORD) {
                    source.sendMessage(MiniMessage.miniMessage().deserialize(config.messageAccountAlreadyType(), Placeholder.component("type", Component.text("password"))));
                    return;
                }
                luckPermsHelper.removeAllAccessFromPlayer(mcUsername);
                sqlDbClient.AddUserToKnownIfNew(mcUsername, true);
                sqlDbClient.SwitchAccountType(mcUsername, true);
                source.sendMessage(MiniMessage.miniMessage().deserialize(config.messageAccountTypeChanged(), Placeholder.component("type", Component.text("password"))));
                logger.info("Account '{}' changed to password authentication.", mcUsername);

            } else if(desiredAccType.equalsIgnoreCase("oidc")) {
                if(sqlDbClient.GetAccountType(mcUsername) == SqlDbClient.accountType.OIDC) {
                    source.sendMessage(MiniMessage.miniMessage().deserialize(config.messageAccountAlreadyType(), Placeholder.component("type", Component.text("OIDC"))));
                    return;
                }
                luckPermsHelper.removeAllAccessFromPlayer(mcUsername);
                sqlDbClient.AddUserToKnownIfNew(mcUsername, false);
                sqlDbClient.SwitchAccountType(mcUsername, false);
                source.sendMessage(MiniMessage.miniMessage().deserialize(config.messageAccountTypeChanged(), Placeholder.component("type", Component.text("OIDC"))));
                logger.info("Account '{}' changed to OIDC authentication.", mcUsername);
            } else {
                source.sendMessage(MiniMessage.miniMessage().deserialize(config.messageCommandIncorrect()));
            }
        } else {
            source.sendMessage(MiniMessage.miniMessage().deserialize(config.messageCommandIncorrect()));
        }

    }

    @Override
    public boolean hasPermission(final Invocation invocation) {
        return invocation.source().hasPermission("oidcauth.manageauth");
    }

    @Override
    public CompletableFuture<List<String>> suggestAsync(final Invocation invocation) {
        String[] args = invocation.arguments();
        if (args.length <= 1) {
            return CompletableFuture.completedFuture(sqlDbClient.getRegisteredPlayernames());
        }
        if (args.length == 2) {
            return CompletableFuture.completedFuture(List.of("unregister", "setAccountType"));
        }
        if (args.length == 3 && args[1].equalsIgnoreCase("setAccountType")) {
            return CompletableFuture.completedFuture(List.of("oidc", "password"));
        }
        return CompletableFuture.completedFuture(List.of());
    }

}
