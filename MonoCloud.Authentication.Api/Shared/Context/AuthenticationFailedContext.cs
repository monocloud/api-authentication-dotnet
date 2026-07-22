namespace MonoCloud.Authentication.Api.Shared.Context;

/// <summary>
/// Context for AuthenticationFailed Event
/// </summary>
public class AuthenticationFailedContext : ResultContext<MonoCloudAuthenticationOptions>
{
  /// <summary>
  /// Context for AuthenticationFailed Event
  /// </summary>
  /// <param name="context"></param>
  /// <param name="scheme"></param>
  /// <param name="options"></param>
  public AuthenticationFailedContext(HttpContext context, AuthenticationScheme scheme, MonoCloudAuthenticationOptions options) : base(context, scheme, options)
  {
  }

  /// <summary>
  /// Gets or sets the exception that caused the authentication process to fail.
  /// </summary>
  /// <remarks>
  /// This property holds the instance of the <see cref="Exception"/> that occurred during the authentication process.
  /// It can be used to capture and log the specific error details for debugging or handling purposes.
  /// </remarks>
  public Exception Exception { get; set; } = default!;
}
