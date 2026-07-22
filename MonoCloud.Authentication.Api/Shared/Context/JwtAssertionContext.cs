namespace MonoCloud.Authentication.Api.Shared.Context;

/// <summary>
/// Context for JwtAssertion Event
/// </summary>
public class JwtAssertionContext : ResultContext<MonoCloudAuthenticationOptions>
{
  /// <summary>
  /// Context for JwtAssertion Event
  /// </summary>
  /// <param name="context"></param>
  /// <param name="scheme"></param>
  /// <param name="options"></param>
  public JwtAssertionContext(HttpContext context, AuthenticationScheme scheme, MonoCloudAuthenticationOptions options) : base(context, scheme, options)
  {
  }

  /// <summary>
  /// Gets or sets the authentication assertion details for a JWT (JSON Web Token).
  /// This includes information such as the assertion itself, the type of assertion,
  /// and the expiration of the cache for the assertion.
  /// </summary>
  public JwtAssertion? JwtAssertion { get; set; }
}
