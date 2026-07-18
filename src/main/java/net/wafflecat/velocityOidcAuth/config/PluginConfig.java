package net.wafflecat.velocityOidcAuth.config;

import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.wafflecat.velocityOidcAuth.VelocityOidcAuthPlugin;
import org.slf4j.Logger;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Loads the plugin's configuration. If the files are not found, it generates them in the data directory
 */

public final class PluginConfig {

    private static Logger logger;
    private static ProxyServer proxyServer;

    private final String providerName;
    private final URI issuer;
    private final String clientId;
    private final String clientSecret;
    private final URI redirectUri;
    private final List<String> scopes;
    private final String usernameClaim;
    private final String UUIDClaim;

    private final String DBType;
    private final String DBHost;
    private final String DBPort;
    private final String DBName;
    private final String DBUser;
    private final String DBPassword;
    private final String DBTablesPrefix;

    private final boolean LDAPEnabled;
    private final String LDAPHost;
    private final int LDAPPort;
    private final String LDAPSearchBase;

    private final String callbackBindAddress;
    private final int callbackBindPort;
    private final String callbackPath;

    private String limboServerName;
    private String fallbackTargetServerName;
    private List<String> defaultServers;

    private long sessionDurationMinutes;
    private long pendingAuthTimeoutMinutes;
    private List<String> allowedCommandsBeforeAuth;

    private String messageOIDCPrompt;
    private String messageLinkHover;
    private String messageAuthSuccess;
    private String messageUserMismatch;
    private String messageAuthError;
    private String messageAlreadyAuthenticated;
    private String messageLoggedOut;
    private String messagePromptPassReg;
    private String messagePromptPassLogin;
    private String messageAlreadyRegistered;
    private String messageAlreadyLoggedOut;
    private String messagePassRegSuccess;
    private String messagePassRegMismatch;
    private String messagePassLoginMismatch;
    private String messageCommandIncorrect;
    private String messageCommandPlayerOnly;
    private String messageAccountTypeChanged;
    private String messageAccountAlreadyType;
    private String messageAccountNotRegistered;
    private String messageAccountUnregistered;
    private String messageValidSession;
    private String messageNoServerPerm;
    private String messageCommandChatRestricted;


    private Map<String, Object> restrictedServers;

    private final Path dataDirectory;


    private PluginConfig(VelocityOidcAuthPlugin plugin, Map<String, Object> staticYaml, Map<String, Object> dynamicYaml) {
        logger = plugin.getLogger();
        proxyServer = plugin.getProxyServer();
        this.dataDirectory = plugin.getDataDirectory();

        Map<String, Object> oidc = section(staticYaml, "oidc");
        this.providerName = getVal(oidc, "provider-name","OIDC Account");
        this.issuer = URI.create(requireVal(oidc, "issuer"));
        this.clientId = requireVal(oidc, "client-id");
        this.clientSecret = requireVal(oidc, "client-secret");
        this.redirectUri = URI.create(requireVal(oidc, "redirect-uri"));
        @SuppressWarnings("unchecked")
        List<String> scopeList = (List<String>) oidc.getOrDefault("scopes", List.of("openid", "profile"));
        this.scopes = scopeList;
        this.usernameClaim = getVal(oidc, "username-claim", "preferred_username");
        this.UUIDClaim = getVal(oidc, "uuid-claim", "uuid");

        Map<String, Object> cb = section(staticYaml, "callback-server");
        this.callbackBindAddress = getVal(cb, "bind-address", "0.0.0.0");
        this.callbackBindPort = getVal(cb, "bind-port", 8085);
        this.callbackPath = getVal(cb, "path", "/login/callback");

        Map<String, Object> database = section(staticYaml, "database");

        this.DBType = requireVal(database, "type").toLowerCase();
        this.DBHost = requireVal(database, "host");
        this.DBPort = requireVal(database, "port");
        this.DBName = requireVal(database, "db");
        this.DBUser = requireVal(database, "user");
        this.DBPassword = requireVal(database, "password");
        this.DBTablesPrefix = requireVal(database, "prefix");

        Map<String, Object> ldap = section(staticYaml, "ldap");

        this.LDAPEnabled = getVal(ldap,"enabled", false);
        this.LDAPHost = getVal(ldap, "host", "ldap.example.com");
        this.LDAPPort = getVal(ldap, "port", 389);
        this.LDAPSearchBase = getVal(ldap, "searchBase", "ou=People,dc=example,dc=com");

        LoadDynamicConfig(dynamicYaml);
        CheckIfConfigServersExist();
        CheckIfDBTypeCorrect();
    }

    public static PluginConfig loadOrCreateDefault(VelocityOidcAuthPlugin plugin) throws IOException {
        Path dataDirectory = plugin.getDataDirectory();
        Files.createDirectories(dataDirectory);
        Path staticConfigPath = dataDirectory.resolve("static-config.yml");
        Path dynamicConfigPath = dataDirectory.resolve("dynamic-config.yml");

        if (!Files.exists(staticConfigPath)) {
            try (InputStream in = PluginConfig.class.getClassLoader().getResourceAsStream("static-config.yml")) {
                if (in == null) {
                    throw new IOException("Bundled default static-config.yml resource is missing from the jar!");
                }
                Files.copy(in, staticConfigPath, StandardCopyOption.REPLACE_EXISTING);
                logger.warn("Wrote default static config to {} - edit it, then restart the proxy.", staticConfigPath);
            }
        }

        if (!Files.exists(dynamicConfigPath)) {
            try (InputStream in = PluginConfig.class.getClassLoader().getResourceAsStream("dynamic-config.yml")) {
                if (in == null) {
                    throw new IOException("Bundled default dynamic-config.yml resource is missing from the jar!");
                }
                Files.copy(in, dynamicConfigPath, StandardCopyOption.REPLACE_EXISTING);
                logger.warn("Wrote default dynamic config to {} - edit it, then restart the proxy.", dynamicConfigPath);
            }
        }

        Yaml yaml = new Yaml();
        Map<String, Object> staticData = null;
        Map<String, Object> dynamicData = null;
        try (InputStream in = Files.newInputStream(staticConfigPath)) {
            staticData = yaml.load(in);
        }

        try (InputStream in = Files.newInputStream(dynamicConfigPath)) {
            dynamicData = yaml.load(in);
        }
        return new PluginConfig(plugin, staticData, dynamicData);
    }

    public void LoadDynamicConfig(Map<String, Object> dynamicYaml)
    {
        Map<String, Object> servers = section(dynamicYaml, "servers");
        this.limboServerName = requireVal(servers, "limbo");
        this.fallbackTargetServerName = requireVal(servers, "fallback-target");
        @SuppressWarnings("unchecked")
        List<String> defaultServers = (List<String>) servers.getOrDefault("default-servers", List.of("limbo"));
        this.defaultServers = defaultServers;
        this.restrictedServers = section(servers, "restricted-servers");

        Map<String, Object> auth = section(dynamicYaml, "auth");
        this.sessionDurationMinutes = getVal(auth, "session-duration-minutes", 720);
        this.pendingAuthTimeoutMinutes = getVal(auth, "pending-auth-timeout-minutes", 3);
        this.allowedCommandsBeforeAuth = (List<String>) auth.getOrDefault("allowed-commands-before-auth", List.of("login", "register", "reg"));

        Map<String, Object> messages = section(dynamicYaml, "messages");
        this.messageOIDCPrompt = getVal(messages, "prompt-oidc", "<yellow>You must sign in before you can play. <blue><u><login_url_click>Click here to authenticate</login_url_click></u></blue>, then you'll be sent through automatically.");
        this.messageLinkHover = getVal(messages, "link-hover", "<gold>Opens OIDC login page in your browser");
        this.messageAuthSuccess = getVal(messages, "auth-success", "<green>Authenticated! Connecting you now...");
        this.messageUserMismatch = getVal(messages, "oidc-user-mismatch", "<red>You authenticated as <white>{identity}</white>, but your Minecraft username is registered to another account. Log in with the matching account and try <white>/login</white> again.");
        this.messageAuthError = getVal(messages, "auth-failed", "<red>Authentication failed: <reason>. Try <white>/login<red> again.");
        this.messageAlreadyAuthenticated = getVal(messages, "already-authenticated", "<green>You're already authenticated.");
        this.messageLoggedOut = getVal(messages, "logged-out", "<red>You have been logged out.");
        this.messagePromptPassReg = getVal(messages, "prompt-pass-reg", "<yellow>You must register before you can play. Please use <blue>/register <password> <password></blue> to register.");
        this.messagePromptPassLogin = getVal(messages, "prompt-pass-login", "<yellow>You must log in before you can play. Please use <blue>/login <password></blue> to authenticate.");
        this.messageAlreadyRegistered = getVal(messages, "already-registered", "<green>You're already registered.");
        this.messageAlreadyLoggedOut = getVal(messages, "already-logged-out", "<red>You're already logged out.");
        this.messagePassRegSuccess = getVal(messages, "pass-reg-success", "<green>Registered successfully!");
        this.messagePassRegMismatch = getVal(messages, "pass-reg-mismatch", "<red>The given passwords don't match!");
        this.messagePassLoginMismatch = getVal(messages, "pass-login-mismatch", "<red>The password you entered is incorrect!");
        this.messageCommandIncorrect = getVal(messages, "command-wrong-usage", "<red>Incorrect command usage.");
        this.messageCommandPlayerOnly = getVal(messages, "command-player-only", "<red>This command can only be used by players.");
        this.messageAccountTypeChanged = getVal(messages, "account-type-changed", "<green>Changed account to <type> authentication.");
        this.messageAccountAlreadyType = getVal(messages, "account-already-type", "<red>This account is already using <type> authentication!");
        this.messageAccountNotRegistered = getVal(messages, "account-not-registered", "<red>The account you are trying to unregister is not registered!");
        this.messageAccountUnregistered = getVal(messages, "account-unregister-success", "<green>Player unregistered successfully.");
        this.messageValidSession = getVal(messages, "valid-session", "<green>You already have a valid session, no need to authenticate!");
        this.messageNoServerPerm = getVal(messages,"no-server-perm", "<red>You do not have permission to join this server!");
        this.messageCommandChatRestricted = getVal(messages, "command-chat-restricted", "<red>You are not allowed to use commands or chat before authentication!");

    }

    // gets ran on startup and when "/velocity reload" command is issued
    public void onProxyReload()
    {
        logger.info("Reloading dynamic configuration");
        Yaml yaml = new Yaml();
        Map<String, Object> dynamicData = null;
        Path dynamicConfigPath = dataDirectory.resolve("dynamic-config.yml");
        try (InputStream in = Files.newInputStream(dynamicConfigPath)) {
            dynamicData = yaml.load(in);
        } catch (IOException e) {
            logger.error("Failed to load dynamic-config.yml! - {}", e.getMessage());
        }
        LoadDynamicConfig(dynamicData);
        CheckIfDBTypeCorrect();
        CheckIfConfigServersExist();
    }

    public void CheckIfConfigServersExist()
    {
        Optional<RegisteredServer> limbo = proxyServer.getServer(limboServerName);
        if(limbo.isEmpty())
        {
            logger.error("Config error! - Configured server '{}' does not exist in velocity.toml!", limboServerName);

        }

        Optional<RegisteredServer> fallback = proxyServer.getServer(fallbackTargetServerName);
        if(fallback.isEmpty())
        {
            logger.error("Config error! - Configured server '{}' does not exist in velocity.toml!", fallbackTargetServerName);
        }

        defaultServers.forEach(serverName -> {
            Optional<RegisteredServer> server = proxyServer.getServer(serverName);
            if(server.isEmpty())
            {
                logger.error("Config error! - Configured server '{}' does not exist in velocity.toml!", serverName);
            }
        });

        restrictedServers.forEach((serverName, LDAPRule) -> {
            Optional<RegisteredServer> server = proxyServer.getServer(serverName);
            if(server.isEmpty())
            {
                logger.error("Config error! - Configured server '{}' does not exist in velocity.toml!", serverName);
            }
        });
    }

    public void CheckIfDBTypeCorrect()
    {
        List<String> possibleDBTypes = List.of("mysql", "mariadb");
        if(!possibleDBTypes.contains(DBType)){
            logger.error("DB Type is configured incorrectly, the plugin will fail to connect! Check your configuration.");
        }
    }

    public List<String> getLDAPQueryWithServername(String servername) {
        @SuppressWarnings("unchecked")
        List<String> ldapQueries = (List<String>) restrictedServers.get(servername);
        return ldapQueries;
    }


    // ---- getters ----

    public String providerName() {
        return providerName;
    }

    public URI issuer() {
        return issuer;
    }

    public String clientId() {
        return clientId;
    }

    public String clientSecret() {
        return clientSecret;
    }

    public URI redirectUri() {
        return redirectUri;
    }

    public List<String> scopes() {
        return scopes;
    }

    public String usernameClaim() {
        return usernameClaim;
    }

    public String UUIDClaim() {
        return UUIDClaim;
    }

    public String DBType() {
        return DBType;
    }

    public String DBHost() {
        return DBHost;
    }

    public String DBPort() {
        return DBPort;
    }

    public String DBName() {
        return DBName;
    }

    public String DBUser() {
        return DBUser;
    }

    public String DBPassword() {
        return DBPassword;
    }

    public String DBTablesPrefix() {
        return DBTablesPrefix;
    }

    public boolean LDAPEnabled() {
        return LDAPEnabled;
    }

    public String LDAPHost() {
        return LDAPHost;
    }

    public int LDAPPort() {
        return LDAPPort;
    }

    public String LDAPSearchBase() {
        return LDAPSearchBase;
    }

    public String callbackBindAddress() {
        return callbackBindAddress;
    }

    public int callbackBindPort() {
        return callbackBindPort;
    }

    public String callbackPath() {
        return callbackPath;
    }

    public String limboServerName() {
        return limboServerName;
    }

    public String fallbackTargetServerName() {
        return fallbackTargetServerName;
    }

    public List<String> getDefaultServers() {
        return defaultServers;
    }

    public long sessionDurationMinutes() {
        return sessionDurationMinutes;
    }

    public long pendingAuthTimeoutMinutes() {
        return pendingAuthTimeoutMinutes;
    }

    public List<String> allowedCommandsBeforeAuth() {
        return allowedCommandsBeforeAuth;
    }

    public String messageOIDCPrompt() {
        return messageOIDCPrompt;
    }

    public String messageLinkHover() {
        return messageLinkHover;
    }

    public String messageAuthSuccess() {
        return messageAuthSuccess;
    }

    public String messageUserMismatch() {
        return messageUserMismatch;
    }

    public String messageAuthError() {
        return messageAuthError;
    }

    public String messageAlreadyAuthenticated() {
        return messageAlreadyAuthenticated;
    }

    public String messageLoggedOut() {
        return messageLoggedOut;
    }

    public String messagePromptPassReg() {
        return messagePromptPassReg;
    }

    public String messagePromptPassLogin() {
        return messagePromptPassLogin;
    }

    public String messageAlreadyRegistered() {
        return messageAlreadyRegistered;
    }

    public String messageAlreadyLoggedOut() {
        return messageAlreadyLoggedOut;
    }

    public String messagePassRegSuccess() {
        return messagePassRegSuccess;
    }

    public String messagePassRegMismatch() {
        return messagePassRegMismatch;
    }

    public String messagePassLoginMismatch() {
        return messagePassLoginMismatch;
    }

    public String messageCommandIncorrect() {
        return messageCommandIncorrect;
    }

    public String messageCommandPlayerOnly() {
        return messageCommandPlayerOnly;
    }

    public String messageAccountTypeChanged() {
        return messageAccountTypeChanged;
    }

    public String messageAccountAlreadyType() {
        return messageAccountAlreadyType;
    }

    public String messageAccountNotRegistered() {
        return messageAccountNotRegistered;
    }

    public String messageAccountUnregistered() {
        return messageAccountUnregistered;
    }

    public String messageValidSession() {
        return messageValidSession;
    }

    public String messageNoServerPerm() {
        return messageNoServerPerm;
    }

    public String messageCommandChatRestricted() {
        return messageCommandChatRestricted;
    }

    public Map<String, Object> getRestrictedServers() {
        return restrictedServers;
    }


    // ---- small yaml helpers ----

    @SuppressWarnings("unchecked")
    private static Map<String, Object> section(Map<String, Object> root, String key) {
        Object v = root.get(key);
        if (!(v instanceof Map)) {
            throw new IllegalArgumentException("Your config.yml is missing required section '" + key + "', check for errors!");
        }
        return (Map<String, Object>) v;
    }

    private static String requireVal(Map<String, Object> section, String key) {
        Object v = section.get(key);
        if (v == null || v.toString().isBlank()) {
            throw new IllegalArgumentException("Your config.yml is missing required value '" + key + "', check for errors!");
        }
        return v.toString();
    }

    private static String getVal(Map<String, Object> section, String key, String def) {
        Object v = section.get(key);
        if(v == null)
        {
            logger.warn("Your config.yml is missing optional string value '{}', using default value for it", key);
            return def;
        } else {
            return v.toString();
        }
    }

    private static int getVal(Map<String, Object> section, String key, int def) {
        Object v = section.get(key);
        if(v == null)
        {
            logger.warn("Your config.yml is missing optional integer value '{}', using default value for it", key);
            return def;
        } else {
            return Integer.parseInt(v.toString());
        }
    }

    private static boolean getVal(Map<String, Object> section, String key, boolean def) {
        Object v = section.get(key);
        if(v == null)
        {
            logger.warn("Your config.yml is missing optional boolean value '{}', using default value for it", key);
            return def;
        } else {
            return  Boolean.parseBoolean(v.toString());
        }
    }
}
