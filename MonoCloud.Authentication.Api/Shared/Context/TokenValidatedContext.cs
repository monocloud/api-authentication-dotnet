namespace MonoCloud.Authentication.Api.Shared.Context;

/// <summary>
/// Context for TokenValidated Event
/// </summary>
public class TokenValidatedContext : ResultContext<MonoCloudAuthenticationOptions>
{
  /// <summary>
  /// Context for TokenValidated Event
  /// </summary>
  /// <param name="context"></param>
  /// <param name="scheme"></param>
  /// <param name="options"></param>
  public TokenValidatedContext(HttpContext context, AuthenticationScheme scheme, MonoCloudAuthenticationOptions options) : base(context, scheme, options)
  {
  }

  /// <summary>
  /// Gets or sets the validated security token associated with the authentication process.
  /// </summary>
  /// <remarks>
  /// This property typically stores the security token (JWT) or string (Opaque) that was successfully
  /// validated during the authentication process. It is managed within the context of a token validation event,
  /// allowing access to the underlying token for further customization or processing.
  /// </remarks>
  public object Token { get; set; } = default!;
}
