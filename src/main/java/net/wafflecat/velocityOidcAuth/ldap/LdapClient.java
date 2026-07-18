package net.wafflecat.velocityOidcAuth.ldap;

import net.wafflecat.velocityOidcAuth.VelocityOidcAuthPlugin;
import net.wafflecat.velocityOidcAuth.config.PluginConfig;
import net.wafflecat.velocityOidcAuth.luckperms.LuckPermsHelper;

import java.util.*;

import javax.naming.*;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.*;

/**
 * Queries the OIDC uid through LDAP to check which cn-s a user is part of,
 * to give access to any restricted servers
 */

public class LdapClient {
    private final String ldapServer;
    private final String ldapSearchBase;
    private final PluginConfig config;

    public LdapClient(VelocityOidcAuthPlugin plugin)
    {
        this.config = plugin.getConfig();
        this.ldapServer = "ldap://" + config.LDAPHost() + ":" + config.LDAPPort();
        this.ldapSearchBase = config.LDAPSearchBase();
    }

    public void syncUserLdap(LuckPermsHelper luckPermsHelper, String oidc_acc, String mcUsername)
    {
        String searchFilter = "(&(uid=" + oidc_acc + ")(objectClass=*))";
        Hashtable<String, Object> env = new Hashtable<String, Object>();
        env.put(Context.SECURITY_AUTHENTICATION, "none");
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapServer);

        LdapContext ctx;
        try
        {
            ctx = new InitialLdapContext(env, null);
            NamingEnumeration results = null;
            try
            {
                String[] reqAtt = { "memberOf" };
                SearchControls controls = new SearchControls();
                controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                controls.setReturningAttributes(reqAtt);
                results = ctx.search(ldapSearchBase, searchFilter, controls);

                while (results.hasMore())
                {
                    SearchResult searchResult = (SearchResult) results.next();
                    Attributes attributes = searchResult.getAttributes();
                    Attribute attr = attributes.get("memberOf");

                    config.getRestrictedServers().keySet().forEach((servername) -> {
                        boolean granted = false;
                        for (int i = 0; i < attr.size(); i++)
                        {
                            try {
                                if(config.getLDAPQueryWithServername(servername).contains(attr.get(i).toString()))
                                {
                                    luckPermsHelper.addPlayerToServerAccessGroup(servername, mcUsername);
                                    granted = true;
                                }
                            } catch (NamingException e) {
                                throw new RuntimeException(e);
                            }
                        }
                        if(!granted) {
                            luckPermsHelper.removePlayerFromServerAccessGroup(servername, mcUsername);
                        }
                    });
                }
            }
            catch (NameNotFoundException e) { }
            catch (NamingException e)
            { throw new RuntimeException(e); }
            finally
            {
                if (results != null) {
                    try { results.close();}
                    catch (Exception e) { }
                }
                if (ctx != null) {
                    try { ctx.close();}
                    catch (Exception e) {  }
                }
            }
        }
        catch (NamingException e)
        {
            e.printStackTrace();
        }
    }
}
