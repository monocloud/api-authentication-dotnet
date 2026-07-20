namespace MonoCloud.Authentication.Api.Shared;

/// <summary>
/// Represents a JWT (JSON Web Token) assertion used for client authentication.
/// This class encapsulates the token (Assertion), its type, and an optional cache expiration time.
/// </summary>
public class JwtAssertion
{
  /// <summary>
  /// Represents an assertion used in a JSON Web Token (JWT).
  /// </summary>
  public string Assertion { get; set; } = string.Empty;

  /// <summary>
  /// Specifies the type of assertion used in a JSON Web Token (JWT).
  /// </summary>
  public string AssertionType { get; set; } = string.Empty;

  /// <summary>
  /// Specifies the expiration time for the cached assertion in a JSON Web Token (JWT).
  /// </summary>
  public DateTime? AssertionCacheExpiry { get; set; }
}
