namespace MonoCloud.Authentication.Api.Shared.ClientAuth;

/// <summary>
/// Represents the SPIFFE X.509-SVID based client authentication mechanism ('spiffe_x509'),
/// performed over mutual TLS.
/// <para>
/// Authentication is performed using an optional X509 certificate (the workload's X.509-SVID).
/// If a certificate is not specified, it is expected that the
/// <see cref="MonoCloudAuthenticationOptions.HttpClient"/> is configured with a message handler
/// that provides the client certificate.
/// </para>
/// <para>
/// Optionally, a trust store id can be provided. If a trust store id is specified,
/// the corresponding trust store will be used to validate the server certificate.
/// If a trust store id is not specified, the default trust store will be used.
/// </para>
/// </summary>
public class SpiffeX509Auth : TlsAuth
{
  /// <summary>
  /// Represents the SPIFFE X.509-SVID based client authentication mechanism ('spiffe_x509'),
  /// performed over mutual TLS.
  /// </summary>
  /// <param name="certificate">The workload's X.509-SVID presented as the TLS client certificate</param>
  /// <param name="trustStore">The id of the trust store used to validate the server certificate</param>
  public SpiffeX509Auth(X509Certificate2? certificate = null, string? trustStore = null) : base(certificate, trustStore)
  {
  }
}
