import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public final class DbevJdbcSmoke {
    private DbevJdbcSmoke() {}

    public static void main(String[] args) throws Exception {
        String host = required("DBE_DRIVER_HOST");
        String port = required("DBE_DRIVER_PORT");
        String tlsPort = required("DBE_DRIVER_TLS_PORT");
        String database = required("DBE_DRIVER_DATABASE");
        String username = required("DBE_DRIVER_USERNAME");
        String password = required("DBE_DRIVER_PASSWORD");

        Class.forName("com.mysql.cj.jdbc.Driver");
        exercise(
            "com.mysql.cj.jdbc.Driver",
            "jdbc:mysql://" + host + ":" + port,
            "?sslMode=DISABLED&connectTimeout=5000&socketTimeout=5000",
            database,
            username,
            password
        );
        exercise(
            "com.mysql.cj.jdbc.Driver",
            "jdbc:mysql://" + host + ":" + tlsPort,
            "?sslMode=REQUIRED&connectTimeout=5000&socketTimeout=5000",
            database,
            username,
            password
        );

        Class.forName("org.mariadb.jdbc.Driver");
        exercise(
            "org.mariadb.jdbc.Driver",
            "jdbc:mariadb://" + host + ":" + port,
            "?sslMode=disable&connectTimeout=5000&socketTimeout=5000",
            database,
            username,
            password
        );
        exercise(
            "org.mariadb.jdbc.Driver",
            "jdbc:mariadb://" + host + ":" + tlsPort,
            "?sslMode=trust&connectTimeout=5000&socketTimeout=5000",
            database,
            username,
            password
        );

        System.out.println("real JDBC/Hikari compatibility smoke passed");
    }

    private static void exercise(
        String driver,
        String baseUrl,
        String options,
        String database,
        String username,
        String password
    ) throws Exception {
        try (Connection connection = DriverManager.getConnection(
            baseUrl + "/" + database + options,
            username,
            password
        )) {
            verify(connection);
        }

        try (Connection connection = DriverManager.getConnection(
            baseUrl + "/" + options,
            username,
            password
        )) {
            connection.setCatalog(database);
            verify(connection);
        }

        HikariConfig config = new HikariConfig();
        config.setPoolName("dbev-" + driver.substring(driver.lastIndexOf('.') + 1));
        config.setDriverClassName(driver);
        config.setJdbcUrl(baseUrl + "/" + options);
        config.setUsername(username);
        config.setPassword(password);
        config.setMaximumPoolSize(2);
        config.setMinimumIdle(0);
        config.setConnectionTimeout(5_000);
        config.setInitializationFailTimeout(10_000);
        try (HikariDataSource dataSource = new HikariDataSource(config);
             Connection connection = dataSource.getConnection()) {
            connection.setCatalog(database);
            verify(connection);
        }
    }

    private static void verify(Connection connection) throws Exception {
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(
                 "SELECT value FROM restore_test WHERE id = 1"
             )) {
            if (!result.next() || !"before".equals(result.getString(1)) || result.next()) {
                throw new IllegalStateException("gateway returned an unexpected JDBC result");
            }
        }
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }
}
