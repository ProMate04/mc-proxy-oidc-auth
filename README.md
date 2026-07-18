# Minecraft Velocity OIDC Auth

This plugin allows you to gate access to backend servers from the proxy side using OIDC/Oauth2 and LDAP.
Alternatively, provides a way to sign in using password (more on this later).
Made to use with Velocity proxy.

## How it works
Velocity allows for forced hosts, which sends joining players directly to a specified backend server, based on the
hostname they joined the server with. Since the plugin only allows players to proceed to said backed servers
after authentication, it first saves the desired server to a cache, and redirects players to a limbo server.
The players are kept here until they successfully authenticate.

### Authentication using OIDC:
Upon the player joining, they get sent a link in the game's chat. Clicking this
opens the OIDC login page in their browser. After successful login, the callback server receives the necessary
data from the OIDC provider.

If this is the first time the player joined the game using a given Minecraft username, the username gets tied
to the OIDC account. If the Minecraft username was already registered with an OIDC account, it checks if the 
correct account was used for sign in.

After that, the plugin queries the LDAP server using the OIDC account's uid (usually username) to grant
access to otherwise restricted backend servers based on configuration.

Following this the player gets sent to the initially desired backend server.

### Authentication using password:
By default, every account uses OIDC for authentication. Any player's account can be toggled to use password 
authentication by an admin. This feature was implemented so admins can give access to certain players who might
not have an OIDC based account. **Only use if you want to give access to a player who in no way can have an OIDC account**

Upon the player joining, if the player has not registered yet, they get asked to do so using `/register <password> <password>`.
If the player is already registered, they get asked to log in using `/login <password>`.

After successfully logging in, the player is sent to the initially desired backend server.

### Sessions
For convenience, once an authentication succeeds, a session is created for the user that is tied to their device.
This means they can disconnect from the server, and upon reconnecting, they will not need to authenticate again
if the session is still valid. By default, a session is valid for 12 hours, this can be changed in the configuration.

### Server permissions (LDAP)
The plugin also gates access to backed servers using permissions. These can be set in the configuration file.
Default servers are servers that every player who authenticated can access. Restricted servers are servers
that only players with the right permissions can access. 

For every server, the plugin creates a LuckPerms group, and gives that group access to the given
backend server. This is done using `oidcauth.serverperm.<servername>` permission, this is what the plugin checks
any time someone tries to join a given backend server.

If a player is authenticated using OIDC, the plugin will sync the user's permission from LDAP, and gives permission
to players for backend servers using LucksPerms API.

If a player is using password authentication, they can still access default servers, but access to restricted
servers will not be synced. You can give them access manually using LuckPerms.

For example: 
If there is a server named `survival`, then the permission you need to give the player is`oidcauth.serverperm.survival`


## Permissions and commands
Every player who uses OIDC authentication can access the following commands:
- `/login` - Sends a login link in game chat
- `/logout` - Invalidates current session, and sends player back to the limbo server for reauthenticating
  
Every player who uses password authentication can access the following commands:
- `/login <password>` - Log in using password
- `/register <password> <password>` - Register using a password
- `/logout` - Invalidates current session, and sends player back to the limbo server for reauthenticating

If a player has the permission `oidcauth.manageauth`, it grants them access to the following commands
(only admins should have these permissions):
- `/oidcauth <player> unregister` - Unregisters a player. On next login, they will be asked to re-register
  (no matter what account type they have)
- `/oidcauth <player> setAccountType <oidc/password>` - Switches between account type for the give player 
**WARNING: This will also unregister the player! They will have to re-register after changing account types!**

## Configuration
The plugin uses two configuration files using YAML formatting. If the files don't exist, the plugin will try to create them.
Check them out, it is commented and explained thoroughly.
- `static-config.yml` - Mostly contains connection details. Only applies changes on full server restart.
- `dynamic-config.yml` - Mostly contains server access details and messages. Applies when the `/velocity reload` is issued.

## Dependencies
This plugin requires a MySQL/MariaDB database and an OIDC provider to be set up.

It also depends on another plugin, LuckPerms to manage permissions

LuckPerms needs to be set up on at least the proxy for the permissions to work.