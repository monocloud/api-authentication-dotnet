namespace MonoCloud.Authentication.Api.Shared;

/// <summary>
/// Represents a JWT (JSON Web Token) assertion used for client authentication.
/// This class encapsulates the token (Assertion) and its type.
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
}
