namespace MonoCloud.Authentication.Api;

/// <summary>
/// Provides events that allow customization of the authentication process in the MonoCloud framework.
/// Contains virtual methods that can be overridden to handle specific authentication-related events.
/// </summary>
/// <remarks>
/// This type derives from <see cref="JwtBearerEvents"/>, so the standard bearer events
/// (<see cref="JwtBearerEvents.OnMessageReceived"/>, <see cref="JwtBearerEvents.OnTokenValidated"/>,
/// <see cref="JwtBearerEvents.OnAuthenticationFailed"/>, <see cref="JwtBearerEvents.OnChallenge"/> and
/// <see cref="JwtBearerEvents.OnForbidden"/>) are available here and are raised for both JWT and
/// opaque (introspected) tokens. The events declared below are the MonoCloud specific additions.
/// </remarks>
public class MonoCloudAuthenticationEvents : JwtBearerEvents
{
  /// <summary>
  /// Invoked after the security token has passed certificate binding validation
  /// </summary>
  public Func<CertificateBindingValidatedContext, Task> OnCertificateBindingValidated { get; set; } = _ => Task.CompletedTask;

  /// <summary>
  /// Invoked before an introspection request is sent.
  /// </summary>
  public Func<IntrospectionRequestContext, Task> OnIntrospection { get; set; } = _ => Task.CompletedTask;

  /// <summary>
  /// Invoked before creating jwt assertion. Users can customize the jwt assertion using this event.
  /// </summary>
  public Func<JwtAssertionContext, Task> OnCreatingJwtAssertion { get; set; } = _ => Task.CompletedTask;

  /// <summary>
  /// Invoked after the security token has passed certificate binding validation
  /// </summary>
  public virtual Task CertificateBindingValidated(CertificateBindingValidatedContext context) => OnCertificateBindingValidated(context);

  /// <summary>
  /// Invoked before an introspection request is sent.
  /// </summary>
  public virtual Task Introspection(IntrospectionRequestContext context) => OnIntrospection(context);

  /// <summary>
  /// Invoked before creating jwt assertion. Users can customize the jwt assertion using this event.
  /// </summary>
  public virtual Task CreatingJwtAssertion(JwtAssertionContext context) => OnCreatingJwtAssertion(context);
}
