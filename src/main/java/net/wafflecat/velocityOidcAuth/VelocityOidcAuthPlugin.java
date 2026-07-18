package net.wafflecat.velocityOidcAuth;

import com.google.inject.Inject;
import com.velocitypowered.api.command.CommandMeta;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyReloadEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Dependency;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;

import net.wafflecat.velocityOidcAuth.cache.AuthSessionCache;
import net.wafflecat.velocityOidcAuth.command.AuthCommand;
import net.wafflecat.velocityOidcAuth.command.LoginCommand;
import net.wafflecat.velocityOidcAuth.command.LogoutCommand;
import net.wafflecat.velocityOidcAuth.command.RegisterCommand;
import net.wafflecat.velocityOidcAuth.config.PluginConfig;
import net.wafflecat.velocityOidcAuth.database.SqlDbClient;
import net.wafflecat.velocityOidcAuth.http.CallbackHttpServer;
import net.wafflecat.velocityOidcAuth.ldap.LdapClient;
import net.wafflecat.velocityOidcAuth.listener.AuthPromptService;
import net.wafflecat.velocityOidcAuth.listener.AuthenticationListener;
import net.wafflecat.velocityOidcAuth.luckperms.LuckPermsHelper;
import net.wafflecat.velocityOidcAuth.oidc.OidcClient;

import net.wafflecat.velocityOidcAuth.util.DeviceFingerprint;
import org.slf4j.Logger;

import java.io.IOException;
import java.nio.file.Path;

@Plugin(
        id = "oidc-auth",
        name = "Velocity OIDC Auth",
        version = "1.6.0",
        description = "OpenID Connect based proxy side player authentication. Optional LDAP querying for permission based backend server access.",
        authors = {"ProMate"},
        dependencies = {@Dependency(id = "luckperms")}
)
public class VelocityOidcAuthPlugin {

    private final ProxyServer proxyServer;
    private final Logger logger;
    private final Path dataDirectory;

    private PluginConfig config;
    private OidcClient oidcClient;
    private AuthSessionCache sessionCache;
    private AuthPromptService promptService;
    private AuthenticationListener authListener;
    private CallbackHttpServer callbackHttpServer;
    private SqlDbClient sqlDbClient;
    private LuckPermsHelper luckPermsHelper;
    private LdapClient ldapClient;

    @Inject
    public VelocityOidcAuthPlugin(ProxyServer proxyServer, Logger logger, @DataDirectory Path dataDirectory) {
        this.proxyServer = proxyServer;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
    }

    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        logger.info("Starting Velocity OIDC Auth plugin...");
        try {
            this.config = PluginConfig.loadOrCreateDefault(this);
        } catch (IOException e) {
            logger.error("Failed to load configs - the plugin will not authenticate anyone until this is fixed!", e);
            return;
        }
        new DeviceFingerprint(logger);
        this.sessionCache = new AuthSessionCache(this);

        try {
            this.oidcClient = new OidcClient(this);
        } catch (Exception e) {
            logger.error("Failed to initialize OIDC client (check 'oidc' section in static-config.yml). "
                    + "The plugin will not authenticate anyone until this is fixed! Exception message: {}", e.getMessage());
            return;
        }

        try {
            this.sqlDbClient = new SqlDbClient(this);
        } catch (Exception e) {
            logger.error("Failed to initialize SQL client (check 'database' section in static-config.yml). "
                    + "The plugin will not authenticate anyone until this is fixed! Exception message: {}", e.getMessage());
            return;
        }
        sqlDbClient.CreateTablesIfNotExists();

        this.luckPermsHelper = new LuckPermsHelper(this);
        luckPermsHelper.createServerAccessGroups(config.getRestrictedServers());
        luckPermsHelper.setDefaultServerAccess(config.getDefaultServers());

        this.ldapClient = new LdapClient(this);
        try {
            this.callbackHttpServer = new CallbackHttpServer(this);
            this.callbackHttpServer.start();
        } catch (IOException e) {
            logger.error("Failed to start the OIDC callback HTTP server on {}:{}. "
                            + "Check that the port is free and 'callback-server' section in static-config.yml are correct. Exception message: {}",
                    config.callbackBindAddress(), config.callbackBindPort(), e.getMessage());
            return;
        }

        this.promptService = new AuthPromptService(this);

        this.authListener = new AuthenticationListener(this);

        // Registering events
        proxyServer.getEventManager().register(this, authListener);
        proxyServer.getEventManager().register(this, sessionCache);

        // Registering commands
        CommandMeta loginMeta = proxyServer.getCommandManager().metaBuilder("login")
                .plugin(this)
                .build();
        proxyServer.getCommandManager().register(loginMeta, new LoginCommand(this));

        CommandMeta logoutMeta = proxyServer.getCommandManager().metaBuilder("logout")
                .plugin(this)
                .build();
        proxyServer.getCommandManager().register(logoutMeta, new LogoutCommand(this));

        CommandMeta registerMeta = proxyServer.getCommandManager().metaBuilder("register")
                .aliases("reg")
                .plugin(this)
                .build();
        proxyServer.getCommandManager().register(registerMeta, new RegisterCommand(this));

        CommandMeta authMeta = proxyServer.getCommandManager().metaBuilder("oidcauth")
                .plugin(this)
                .build();
        proxyServer.getCommandManager().register(authMeta, new AuthCommand(this));


        logger.info("Velocity OIDC Auth successfully loaded. Callback listening on {}:{} (public redirect-uri: {}). "
                        + "Unauthenticated players will be held on '{}'.",
                config.callbackBindAddress(), config.callbackBindPort(), config.redirectUri(), config.limboServerName());
    }

    // gets ran when "/velocity reload" command is issued
    @Subscribe
    public void onProxyReload(ProxyReloadEvent event) {
        config.onProxyReload();
        luckPermsHelper.createServerAccessGroups(config.getRestrictedServers());
        luckPermsHelper.setDefaultServerAccess(config.getDefaultServers());
    }

    @Subscribe
    public void onProxyShutdown(ProxyShutdownEvent event) {
        if (callbackHttpServer != null) {
            callbackHttpServer.stop();
        }
        if (sqlDbClient != null) {
            sqlDbClient.stopDBConnection();
        }

    }

    public PluginConfig getConfig() {
        return config;
    }

    public Logger getLogger() {
        return logger;
    }

    public ProxyServer getProxyServer() {
        return proxyServer;
    }

    public Path getDataDirectory() {
        return dataDirectory;
    }

    public OidcClient getOidcClient() {
        return oidcClient;
    }

    public AuthSessionCache getSessionCache() {
        return sessionCache;
    }

    public AuthPromptService getAuthPromptService() {
        return promptService;
    }

    public AuthenticationListener getAuthListener() {
        return authListener;
    }

    public CallbackHttpServer getCallbackHttpServer() {
        return callbackHttpServer;
    }

    public SqlDbClient getSqlDbClient() {
        return sqlDbClient;
    }

    public LuckPermsHelper getLuckPermsHelper() {
        return luckPermsHelper;
    }

    public LdapClient getLdapClient() {
        return ldapClient;
    }

}
