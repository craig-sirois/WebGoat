package org.owasp.webgoat.container.lessons;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.regex.Pattern;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Handler which sets the correct schema for the currently bounded user. This way users are not
 * seeing each other data, and we can reset data for just one particular user.
 */
public class LessonConnectionInvocationHandler implements InvocationHandler {

  private final Connection targetConnection;
  
  // Pattern to detect schema-qualified table references (e.g., SCHEMA.TABLE or "SCHEMA".TABLE)
  private static final Pattern SCHEMA_QUALIFIED_PATTERN = 
      Pattern.compile("(?i)\\b([A-Za-z0-9_\"]+)\\s*\\.\\s*[A-Za-z0-9_\"]+");

  public LessonConnectionInvocationHandler(Connection targetConnection) {
    this.targetConnection = targetConnection;
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    var authentication = SecurityContextHolder.getContext().getAuthentication();
    String currentUsername = null;
    if (authentication != null && authentication.getPrincipal() instanceof WebGoatUser user) {
      currentUsername = user.getUsername();
      try (var statement = targetConnection.createStatement()) {
        statement.execute("SET SCHEMA \"" + currentUsername + "\"");
      }
    }
    
    // Validate SQL queries to prevent cross-schema access
    if (currentUsername != null && args != null && args.length > 0) {
      String methodName = method.getName();
      // Intercept both Statement execution methods and PreparedStatement creation methods
      if (methodName.equals("executeQuery") || methodName.equals("execute") || 
          methodName.equals("executeUpdate") || methodName.equals("prepareStatement") || 
          methodName.equals("prepareCall")) {
        if (args[0] instanceof String sql) {
          validateSqlQuery(sql, currentUsername);
        }
      }
    }
    
    try {
      return method.invoke(targetConnection, args);
    } catch (InvocationTargetException e) {
      throw e.getTargetException();
    }
  }
  
  /**
   * Validates that the SQL query does not attempt to access schemas other than the current user's schema.
   * This prevents cross-user data access and access to the CONTAINER schema which contains sensitive data.
   */
  private void validateSqlQuery(String sql, String currentUsername) throws SQLException {
    // Check for schema-qualified references
    var matcher = SCHEMA_QUALIFIED_PATTERN.matcher(sql);
    while (matcher.find()) {
      String schemaReference = matcher.group(1);
      // Remove quotes if present
      String normalizedSchema = schemaReference.replaceAll("\"", "").toUpperCase();
      String normalizedUsername = currentUsername.toUpperCase();
      
      // Block access to CONTAINER schema and other users' schemas
      if (normalizedSchema.equals("CONTAINER") || !normalizedSchema.equals(normalizedUsername)) {
        throw new SQLException(
            "Access denied: Cannot access schema '" + schemaReference + "'. " +
            "Queries are restricted to the current user's schema only.");
      }
    }
  }
}
