namespace MonoCloud.Authentication.Api.Shared.Context;

/// <summary>
/// Context for CertificateBinding Event
/// </summary>
public class CertificateBindingValidatedContext : ResultContext<MonoCloudAuthenticationOptions>
{
  /// <summary>
  /// Context for CertificateBinding Event
  /// </summary>
  /// <param name="context"></param>
  /// <param name="scheme"></param>
  /// <param name="options"></param>
  public CertificateBindingValidatedContext(HttpContext context, AuthenticationScheme scheme, MonoCloudAuthenticationOptions options) : base(context, scheme, options)
  {
  }
}
