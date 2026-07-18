package net.wafflecat.velocityOidcAuth.luckperms;

import net.luckperms.api.LuckPerms;
import net.luckperms.api.LuckPermsProvider;
import net.luckperms.api.model.group.Group;
import net.luckperms.api.model.user.User;
import net.luckperms.api.node.Node;
import net.luckperms.api.node.types.InheritanceNode;
import net.luckperms.api.node.types.RegexPermissionNode;
import net.wafflecat.velocityOidcAuth.VelocityOidcAuthPlugin;
import org.slf4j.Logger;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

/**
 * Provides methods to manage permissions for players using the LucKPerms API
 * Because of this, LuckPerms is required for the plugin to work
 */

public class LuckPermsHelper
{
    private final Logger logger;
    private LuckPerms luckPermsAPI;

    public LuckPermsHelper(VelocityOidcAuthPlugin plugin)
    {
        this.logger = plugin.getLogger();
        try {
            this.luckPermsAPI = LuckPermsProvider.get();
        } catch (Exception e) {
            logger.error("Failed to get an instance of LuckPerms API, is the plugin installed? Exception message: {}", e.getMessage());
        }

    }

    public void createServerAccessGroups(Map<String, Object> restictedServers)
    {
        restictedServers.keySet().forEach((servername) -> {
            if (luckPermsAPI.getGroupManager().getGroup(servername) == null) {
                CompletableFuture<Group> futureGroup = luckPermsAPI.getGroupManager().createAndLoadGroup(servername);
                logger.info("Created LuckPerms group {}", servername);
                try {
                    futureGroup.get().data().add(Node.builder("oidcauth.serverperm." + servername).build());
                    luckPermsAPI.getGroupManager().saveGroup(futureGroup.get());
                } catch (InterruptedException | ExecutionException e) {
                    throw new RuntimeException(e);
                }
            } else {
                Group group = luckPermsAPI.getGroupManager().getGroup(servername);
                group.data().add(Node.builder("oidcauth.serverperm." + servername).build());
                luckPermsAPI.getGroupManager().saveGroup(group);
            }
        });
    }
    public void setDefaultServerAccess(List<String> defaultServers)
    {
        Group group = luckPermsAPI.getGroupManager().getGroup("default");
        group.data().remove(RegexPermissionNode.builder("oidcauth\\.serverperm\\.*").build());
        luckPermsAPI.getGroupManager().saveGroup(group);
        //group.data().clear();
        defaultServers.forEach((servername) -> {
            logger.info("Adding default access for server '{}'...", servername);
            group.data().add(Node.builder("oidcauth.serverperm." + servername).build());
            luckPermsAPI.getGroupManager().saveGroup(group);
        });
    }

    public void addPlayerToServerAccessGroup(String servername, String mcUsername)
    {
        getLuckpermsUser(mcUsername).thenAcceptAsync(user -> {
            Group group = luckPermsAPI.getGroupManager().getGroup(servername);
            user.data().add(InheritanceNode.builder(group).build());
            luckPermsAPI.getUserManager().saveUser(user);
            logger.info("Granting '{}' access to '{}'", mcUsername, servername);
        });
    }

    public void removePlayerFromServerAccessGroup(String servername, String mcUsername)
    {
        getLuckpermsUser(mcUsername).thenAcceptAsync(user -> {
            Group group = luckPermsAPI.getGroupManager().getGroup(servername);
            user.data().remove(InheritanceNode.builder(group).build());
            luckPermsAPI.getUserManager().saveUser(user);
            logger.info("Revoking '{}' access to '{}'", mcUsername, servername);
        });
    }

    public void removeAllAccessFromPlayer(String mcUsername)
    {
        getLuckpermsUser(mcUsername).thenAcceptAsync(user -> {
            user.data().clear();
            luckPermsAPI.getUserManager().saveUser(user);
            logger.info("Revoking all access for '{}'", mcUsername);
        });
    }

    public CompletableFuture<User> getLuckpermsUser(String mcUsername)
    {
        String seed = "OfflinePlayer:" + mcUsername;
        UUID playerUUID = UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8));
        return luckPermsAPI.getUserManager().loadUser(playerUUID);
    }

}
