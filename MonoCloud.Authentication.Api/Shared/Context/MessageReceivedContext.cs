namespace MonoCloud.Authentication.Api.Shared.Context;

/// <summary>
/// Context for MessageReceived Event
/// </summary>
public class MessageReceivedContext : ResultContext<MonoCloudAuthenticationOptions>
{
  /// <summary>
  /// Context for MessageReceived Event
  /// </summary>
  /// <param name="context"></param>
  /// <param name="scheme"></param>
  /// <param name="options"></param>
  public MessageReceivedContext(HttpContext context, AuthenticationScheme scheme, MonoCloudAuthenticationOptions options) : base(context, scheme, options)
  {
  }

  /// <summary>
  /// Gets or sets the token received in a message context during authentication.
  /// </summary>
  /// <remarks>
  /// This property is typically used to access or modify the token supplied
  /// during the processing of authentication in the <see cref="MessageReceivedContext"/>.
  /// The token can be used for validation or further processing based on the
  /// authentication requirements.
  /// </remarks>
  public string? Token { get; set; }
}
