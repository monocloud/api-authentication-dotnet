namespace MonoCloud.Authentication.Api;

/// <summary>
/// Provides events that allow customization of the authentication process in the MonoCloud framework.
/// Contains virtual methods that can be overridden to handle specific authentication-related events.
/// </summary>
public class MonoCloudAuthenticationEvents
{
  /// <summary>
  /// Invoked if exceptions are thrown during request processing. The exceptions will be re-thrown after this event unless suppressed.
  /// </summary>
  public Func<AuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; } = _ => Task.CompletedTask;

  /// <summary>
  /// Invoked after the security token has passed validation and a ClaimsIdentity has been generated.
  /// </summary>
  public Func<TokenValidatedContext, Task> OnTokenValidated { get; set; } = _ => Task.CompletedTask;

  /// <summary>
  /// Invoked after the security token has passed certificate binding validation
  /// </summary>
  public Func<CertificateBindingValidatedContext, Task> OnCertificateBindingValidated { get; set; } = _ => Task.CompletedTask;

  /// <summary>
  /// Invoked when a protocol message is first received.
  /// </summary>
  public Func<MessageReceivedContext, Task> OnMessageReceived { get; set; } = _ => Task.CompletedTask;

  /// <summary>
  /// Invoked before an introspection request is sent.
  /// </summary>
  public Func<IntrospectionRequestContext, Task> OnIntrospection { get; set; } = _ => Task.CompletedTask;

  /// <summary>
  /// Invoked before creating jwt assertion. Users can customize the jwt assertion using this event.
  /// </summary>
  public Func<JwtAssertionContext, Task> OnCreatingJwtAssertion { get; set; } = _ => Task.CompletedTask;

  /// <summary>
  /// Invoked if exceptions are thrown during request processing. The exceptions will be re-thrown after this event unless suppressed.
  /// </summary>
  public virtual Task AuthenticationFailed(AuthenticationFailedContext context) => OnAuthenticationFailed(context);

  /// <summary>
  /// Invoked after the security token has passed validation and a ClaimsIdentity has been generated.
  /// </summary>
  public virtual Task TokenValidated(TokenValidatedContext context) => OnTokenValidated(context);

  /// <summary>
  /// Invoked after the security token has passed certificate binding validation
  /// </summary>
  public virtual Task CertificateBindingValidated(CertificateBindingValidatedContext context) => OnCertificateBindingValidated(context);

  /// <summary>
  /// Invoked when a protocol message is first received.
  /// </summary>
  public virtual Task MessageReceived(MessageReceivedContext context) => OnMessageReceived(context);

  /// <summary>
  /// Invoked before an introspection request is sent.
  /// </summary>
  public virtual Task Introspection(IntrospectionRequestContext context) => OnIntrospection(context);

  /// <summary>
  /// Invoked before creating jwt assertion. Users can customize the jwt assertion using this event.
  /// </summary>
  public virtual Task CreatingJwtAssertion(JwtAssertionContext context) => OnCreatingJwtAssertion(context);
}
