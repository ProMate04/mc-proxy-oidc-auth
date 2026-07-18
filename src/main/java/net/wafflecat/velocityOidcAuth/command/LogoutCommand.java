package net.wafflecat.velocityOidcAuth.command;

import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.kyori.adventure.key.Key;
import net.kyori.adventure.text.minimessage.MiniMessage;
import net.wafflecat.velocityOidcAuth.VelocityOidcAuthPlugin;
import net.wafflecat.velocityOidcAuth.cache.AuthSessionCache;
import net.wafflecat.velocityOidcAuth.config.PluginConfig;
import net.wafflecat.velocityOidcAuth.util.DeviceFingerprint;
import org.slf4j.Logger;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Lets a player invalidate their session, sending them back to limbo,
 * and requiring re-authentication
 */
public final class LogoutCommand implements SimpleCommand {

    private final PluginConfig config;
    private final Logger logger;
    private final AuthSessionCache sessionCache;
    private final ProxyServer proxyServer;

    public LogoutCommand(VelocityOidcAuthPlugin plugin) {
        this.config = plugin.getConfig();
        this.logger = plugin.getLogger();
        this.sessionCache = plugin.getSessionCache();
        this.proxyServer = plugin.getProxyServer();
    }

    @Override
    public void execute(Invocation invocation) {
        if (!(invocation.source() instanceof Player player)) {
            invocation.source().sendMessage(MiniMessage.miniMessage().deserialize(config.messageCommandPlayerOnly()));
            return;
        }

        if (sessionCache.isAuthenticated(player)) {
            // if the player was actually logged in

            sessionCache.invalidateSession(player.getUsername());
            Optional<RegisteredServer> target = proxyServer.getServer(config.limboServerName());

            player.createConnectionRequest(target.get()).connect();
            player.sendMessage(MiniMessage.miniMessage().deserialize(config.messageLoggedOut()));
            player.storeCookie(Key.key("oidcauth", "session_token"), "".getBytes(StandardCharsets.UTF_8));
            logger.info("Logged out | Minecraft username: '{}'", player.getUsername());
        } else{
            player.sendMessage(MiniMessage.miniMessage().deserialize(config.messageAlreadyLoggedOut()));
        }
        return;

    }
}
