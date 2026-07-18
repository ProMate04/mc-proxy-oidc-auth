package net.wafflecat.velocityOidcAuth.database;

import net.wafflecat.velocityOidcAuth.VelocityOidcAuthPlugin;
import org.mindrot.jbcrypt.BCrypt;
import net.wafflecat.velocityOidcAuth.cache.AuthSessionCache;
import net.wafflecat.velocityOidcAuth.config.PluginConfig;
import org.slf4j.Logger;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Properties;

/**
 * Provides methods for connecting to database, and retrieving data
 */

public class SqlDbClient {

    private final PluginConfig config;
    private final Logger logger;
    private Connection DBConnection;
    private final AuthSessionCache sessionCache;

    public enum accountType {
        NONE,
        OIDC,
        PASSWORD
    }

    public SqlDbClient(VelocityOidcAuthPlugin plugin) {

        this.config = plugin.getConfig();
        this.logger = plugin.getLogger();
        this.sessionCache = plugin.getSessionCache();
        reconnectToDB();
    }

    public void reconnectToDB()
    {
        try {
            switch(config.DBType())
            {
                case "mysql":
                    Class.forName("com.mysql.cj.jdbc.Driver");
                    break;
                case "mariadb":
                    Class.forName("org.mariadb.jdbc.Driver");
                    break;
                default:
                    logger.error("DB Type is configured incorrectly! Check your configuration.");
                    return;
            }

            Properties props = new Properties();
            props.setProperty("user", config.DBUser());
            props.setProperty("password", config.DBPassword());
            props.setProperty("connectRetryCount", "20");
            props.setProperty("connectRetryInterval", "3");
            props.setProperty("autoReconnect", "true"); // for some reason this shit does nothing

            String DBUrl = "jdbc:" + config.DBType() +"://" + config.DBHost() + ":" + config.DBPort() + "/" + config.DBName();
            this.DBConnection = DriverManager.getConnection(DBUrl, props);
            logger.info("Connected to database using {}", DBUrl);
            //DBConnection = DriverManager.getConnection(DBUrl, config.DBUser(), config.DBPassword() );
        } catch (Exception e) {
            logger.error("Could not connect to database!! - {}", e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public void CheckIfConnectionIsValid()
    {
        try{
            Statement statement = DBConnection.createStatement();
            ResultSet resultSet = statement.executeQuery("SHOW TABLES LIKE '" + config.DBTablesPrefix() + "_allKnownUsers'");
            while (resultSet.next()) { }
        } catch (Exception e) {
            logger.warn("Database seems to be disconnected, trying to reconnect... " + e.getMessage());
            reconnectToDB();
        }
    }


    public void CreateTablesIfNotExists() {
        CheckIfConnectionIsValid();
        try {
            // Create statement
            Statement statement = DBConnection.createStatement();
            // Execute query
            ResultSet resultSet = statement.executeQuery("SHOW TABLES LIKE '" + config.DBTablesPrefix() + "_allKnownUsers'");

            int rowCount = 0;
            // Process results
            while (resultSet.next()) {
                rowCount++;
            }

            if (rowCount == 0) {
                statement.executeUpdate("CREATE TABLE " + config.DBTablesPrefix() + "_allKnownUsers (mcUsername VARCHAR(255) PRIMARY KEY, usesPassword BOOLEAN NOT NULL, isRegistered BOOLEAN NOT NULL)");
                statement.executeUpdate("CREATE TABLE " + config.DBTablesPrefix() + "_oidcUsers (mcUsername VARCHAR(255) PRIMARY KEY, oidc_uuid VARCHAR(36) NOT NULL, oidc_username VARCHAR(255) NOT NULL)");
                statement.executeUpdate("CREATE TABLE " + config.DBTablesPrefix() + "_passwordUsers (mcUsername VARCHAR(255) PRIMARY KEY, passwordHash VARCHAR(60) NOT NULL)");
                logger.info("Database tables created");
            } else {
                logger.info("Database tables already exist");
            }

            resultSet.close();
            statement.close();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public accountType GetAccountType(String mcUsername)
    {
        CheckIfConnectionIsValid();
        try {
            String query = "SELECT * FROM " + config.DBTablesPrefix() + "_allKnownUsers WHERE mcUsername = ?";
            PreparedStatement statement = DBConnection.prepareStatement(query);
            statement.setString(1, mcUsername);

            ResultSet resultSet = statement.executeQuery();

            accountType accType = accountType.NONE;
            while (resultSet.next()) {
                if(resultSet.getBoolean("usesPassword")) {
                    accType = accountType.PASSWORD;
                } else {
                    accType = accountType.OIDC;
                }
            }
            resultSet.close();
            statement.close();

            return accType;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public boolean AddUserToKnownIfNew(String mcUsername, boolean usesPassword)
    {
        CheckIfConnectionIsValid();
        if(GetAccountType(mcUsername) == accountType.NONE) {
            try {
                String query = "INSERT INTO " + config.DBTablesPrefix() + "_allKnownUsers VALUES (?,?,?)";
                PreparedStatement statement = DBConnection.prepareStatement(query);
                statement.setString(1, mcUsername);
                statement.setBoolean(2, usesPassword); // usesPassword
                statement.setBoolean(3, false); // isRegistered
                statement.executeUpdate();
                statement.close();
                return true;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        return false;
    }

    public boolean SwitchAccountType(String mcUsername, boolean usesPassword)
    {
        CheckIfConnectionIsValid();
        if(CheckIfUserIsRegistered(mcUsername)) {
            UnregisterUser(mcUsername);
        }
        try {
            String query = "UPDATE " + config.DBTablesPrefix() + "_allKnownUsers SET usesPassword = ?, isRegistered = ? WHERE mcUsername = ?";
            PreparedStatement statement = DBConnection.prepareStatement(query);
            statement.setBoolean(1, usesPassword); // usesPassword
            statement.setBoolean(2, false); // isRegistered
            statement.setString(3, mcUsername);

            statement.executeUpdate();
            statement.close();
            return true;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public boolean CheckIfUserIsRegistered(String mcUsername)
    {
        CheckIfConnectionIsValid();
        try {
            String query = "SELECT * FROM " + config.DBTablesPrefix() + "_allKnownUsers WHERE mcUsername = ?";
            PreparedStatement statement = DBConnection.prepareStatement(query);
            statement.setString(1, mcUsername);

            ResultSet resultSet = statement.executeQuery();

            while (resultSet.next()) {
                if(resultSet.getBoolean("isRegistered")) {
                    resultSet.close();
                    statement.close();
                    return true;
                }
            }
            resultSet.close();
            statement.close();
            return false;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /*
    public boolean CheckIfOIDCUserExists(String mcUsername)
    {
        CheckIfConnectionIsValid();
        try {
            String query = "SELECT * FROM " + config.DBTablesPrefix() + "_allKnownUsers WHERE mcUsername = ?";
            PreparedStatement statement = DBConnection.prepareStatement(query);
            statement.setString(1, mcUsername);

            ResultSet resultSet = statement.executeQuery();

            boolean exists = false;
            while (resultSet.next()) {
                if(!resultSet.getBoolean("usesPassword")) {exists = true;}
            }
            resultSet.close();
            statement.close();

            return exists;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    } */

    /*
    public boolean CheckIfPassUserBeforeReg(String mcUsername)
    {
        CheckIfConnectionIsValid();
        try {
            String query = "SELECT * FROM " + config.DBTablesPrefix() + "_allKnownUsers WHERE mcUsername = ?";
            PreparedStatement statement = DBConnection.prepareStatement(query);
            statement.setString(1, mcUsername);

            ResultSet resultSet = statement.executeQuery();

            boolean exists = false;
            while (resultSet.next()) {
                if(resultSet.getBoolean("usesPassword") && !resultSet.getBoolean("isRegistered")) {exists = true;}
            }
            resultSet.close();
            statement.close();

            return exists;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }*/

    /*
    public boolean CheckIfPassUserExists(String mcUsername)
    {
        CheckIfConnectionIsValid();
        try {
            String query = "SELECT * FROM " + config.DBTablesPrefix() + "_allKnownUsers WHERE mcUsername = ?";
            PreparedStatement statement = DBConnection.prepareStatement(query);
            statement.setString(1, mcUsername);

            ResultSet resultSet = statement.executeQuery();

            boolean exists = false;
            while (resultSet.next()) {
                if(resultSet.getBoolean("usesPassword") && resultSet.getBoolean("isRegistered")) {exists = true;}
            }
            resultSet.close();
            statement.close();

            return exists;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    */

    public boolean CheckIfOIDCAccMatches(String mcUsername, String oidc_uuid)
    {
        CheckIfConnectionIsValid();
        try {
            String query = "SELECT * FROM " + config.DBTablesPrefix() + "_oidcUsers WHERE mcUsername = ?";
            PreparedStatement statement = DBConnection.prepareStatement(query);
            statement.setString(1, mcUsername);

            ResultSet resultSet = statement.executeQuery();

            while (resultSet.next()) {
                String savedOIDCAccUUID = resultSet.getString("oidc_uuid");
                resultSet.close();
                statement.close();
                if(Objects.equals(oidc_uuid, savedOIDCAccUUID))
                {
                    return true;
                } else {
                    return false;
                }
            }
            return false; // should not be able to get here
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public boolean CheckIfPassMatches(String mcUsername, String password)
    {
        CheckIfConnectionIsValid();
        try {
            String query = "SELECT * FROM " + config.DBTablesPrefix() + "_passwordUsers WHERE mcUsername = ?";
            PreparedStatement statement = DBConnection.prepareStatement(query);
            statement.setString(1, mcUsername);

            // Execute query
            ResultSet resultSet = statement.executeQuery();

            while (resultSet.next()) {
                String savedPasswordHash = resultSet.getString("passwordHash");
                resultSet.close();
                statement.close();
                return BCrypt.checkpw(password, savedPasswordHash);
            }
            return false; // should not be able to get here
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void RegisterOIDCUser(String mcUsername, String oidc_uuid, String oidc_username)
    {
        CheckIfConnectionIsValid();
        try {

            String query = "UPDATE " + config.DBTablesPrefix() + "_allKnownUsers SET usesPassword = ?, isRegistered = ? WHERE mcUsername = ?";
            PreparedStatement statement = DBConnection.prepareStatement(query);
            statement.setBoolean(1, false); // usesPassword
            statement.setBoolean(2, true); // isRegistered
            statement.setString(3, mcUsername);
            statement.executeUpdate();

            query = "INSERT INTO " + config.DBTablesPrefix() + "_oidcUsers VALUES (?,?,?)";
            statement = DBConnection.prepareStatement(query);
            statement.setString(1, mcUsername);
            statement.setString(2, oidc_uuid);
            statement.setString(3, oidc_username);
            statement.executeUpdate();

            statement.close();
            return;
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void RegisterPasswordUser(String mcUsername, String password)
    {
        CheckIfConnectionIsValid();

        String passwordHash = BCrypt.hashpw(password, BCrypt.gensalt(10));
        try
        {
            String query = "UPDATE " + config.DBTablesPrefix() + "_allKnownUsers SET usesPassword = ?, isRegistered = ? WHERE mcUsername = ?";
            PreparedStatement statement = DBConnection.prepareStatement(query);
            statement.setBoolean(1, true); // usesPassword
            statement.setBoolean(2, true); // isRegistered
            statement.setString(3, mcUsername);
            statement.executeUpdate();

            query = "INSERT INTO " + config.DBTablesPrefix() + "_passwordUsers VALUES (?,?)";
            statement = DBConnection.prepareStatement(query);
            statement.setString(1, mcUsername);
            statement.setString(2, passwordHash);
            statement.executeUpdate();

            statement.close();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public boolean UnregisterUser(String mcUsername)
    {
        CheckIfConnectionIsValid();
        try {
            if(GetAccountType(mcUsername) != accountType.NONE) {
                boolean usesPassword = GetAccountType(mcUsername) == accountType.PASSWORD;
                sessionCache.invalidateSession(mcUsername);

                String query = "UPDATE " + config.DBTablesPrefix() + "_allKnownUsers SET usesPassword = ?, isRegistered = ? WHERE mcUsername = ?";
                PreparedStatement statement = DBConnection.prepareStatement(query);
                statement.setBoolean(1, usesPassword); // usesPassword
                statement.setBoolean(2, false); // isRegistered
                statement.setString(3, mcUsername);
                statement.executeUpdate();

                if(usesPassword) {
                    query = "DELETE FROM " + config.DBTablesPrefix() + "_passwordUsers WHERE mcUsername = ?";
                } else {
                    query = "DELETE FROM " + config.DBTablesPrefix() + "_oidcUsers WHERE mcUsername = ?";
                }
                statement = DBConnection.prepareStatement(query);
                statement.setString(1, mcUsername);
                statement.executeUpdate();

                statement.close();
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /*
    public boolean UnregisterPasswordUser(String mcUsername)
    {
        try {
            if(GetAccountType(mcUsername) ==  accountType.PASSWORD)
            {
                sessionCache.invalidateSession(mcUsername);

                String query = "UPDATE " + config.DBTablesPrefix() + "_allKnownUsers SET 'usesPassword' = ?, 'isRegistered' = ? WHERE mcUsername = ?";
                PreparedStatement statement = DBConnection.prepareStatement(query);
                statement.setString(1, mcUsername);
                statement.setBoolean(2, true); // usesPassword
                statement.setBoolean(3, false); // isRegistered
                statement.executeUpdate();

                query = "DELETE FROM " + config.DBTablesPrefix() + "_passwordUsers WHERE mcUsername = ?";
                statement = DBConnection.prepareStatement(query);
                statement.setString(1, mcUsername);
                statement.executeUpdate();

                statement.close();
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    */

    public List<String> getRegisteredPlayernames()
    {
        CheckIfConnectionIsValid();
        try {

            String query = "SELECT * FROM " + config.DBTablesPrefix() + "_allKnownUsers";
            // Execute query
            PreparedStatement statement = DBConnection.prepareStatement(query);
            ResultSet resultSet = statement.executeQuery();

            List<String> playernames = new ArrayList<String>();
            while (resultSet.next()) {
                playernames.add(resultSet.getString("mcUsername"));
            }
            resultSet.close();
            statement.close();
            return playernames;


        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void stopDBConnection()
    {
        try {
            DBConnection.close();
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


}
