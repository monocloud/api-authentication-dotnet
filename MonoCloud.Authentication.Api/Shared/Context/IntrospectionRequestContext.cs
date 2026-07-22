namespace MonoCloud.Authentication.Api.Shared.Context;

/// <summary>
/// Context for IntrospectionRequest Event
/// </summary>
public class IntrospectionRequestContext : ResultContext<MonoCloudAuthenticationOptions>
{
  /// <summary>
  /// Context for IntrospectionRequest Event
  /// </summary>
  /// <param name="context"></param>
  /// <param name="scheme"></param>
  /// <param name="options"></param>
  public IntrospectionRequestContext(HttpContext context, AuthenticationScheme scheme, MonoCloudAuthenticationOptions options) : base(context, scheme, options)
  {
  }

  /// <summary>
  /// Gets or sets the HTTP request message associated with the introspection process.
  /// </summary>
  /// <remarks>
  /// This property holds the <see cref="HttpRequestMessage"/> used for sending requests during the
  /// token introspection process within the authentication flow.
  /// </remarks>
  public HttpRequestMessage IntrospectionRequest { get; set; } = default!;
}
