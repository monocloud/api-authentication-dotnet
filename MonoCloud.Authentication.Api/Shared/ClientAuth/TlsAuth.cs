namespace MonoCloud.Authentication.Api.Shared.ClientAuth;

/// <summary>
/// Provides TLS-based authentication for client applications using mutual TLS (mTLS).
/// This class implements the <see cref="IMonoCloudClientAuth"/> interface.
/// <para>
/// Authentication is performed using an optional X509 certificate. If a certificate is not
/// specified, it is expected that the <see cref="MonoCloudAuthenticationOptions.HttpClient"/>
/// is configured with a message handler that provides the client certificate.
/// </para>
/// <para>
/// Optionally, a trust store id can be provided. If a trust store id is specified,
/// the corresponding trust store will be used to validate the server certificate.
/// If a trust store id is not specified, the default trust store will be used.
/// </para>
/// </summary>

public class TlsAuth : IMonoCloudClientAuth
{
  internal readonly string? TrustStore;

  /// <summary>
  /// Provides TLS-based authentication for client applications using mutual TLS (mTLS).
  /// This class implements the <see cref="IMonoCloudClientAuth"/> interface.
  /// <para>
  /// Authentication is performed using an optional X509 certificate. If a certificate is not
  /// specified, it is expected that the <see cref="MonoCloudAuthenticationOptions.HttpClient"/>
  /// is configured with a message handler that provides the client certificate.
  /// </para>
  /// <para>
  /// Optionally, a trust store id can be provided. If a trust store id is specified,
  /// the corresponding trust store will be used to validate the server certificate.
  /// If a trust store id is not specified, the default trust store will be used.
  /// </para>
  /// </summary>
  public TlsAuth(X509Certificate2? certificate = null, string? trustStore = null)
  {
    TrustStore = trustStore;
    Certificate = certificate;
  }

  internal X509Certificate2? Certificate { get; }

  /// <inheritdoc />
  public Task AuthenticateAsync(ClientAuthenticationContext context, CancellationToken cancellationToken)
  {
    if (string.IsNullOrEmpty(context.Options.ClientId))
    {
      throw new ArgumentNullException(nameof(context.Options.ClientId), "ClientId must be set");
    }

    context.IntrospectionRequestPayload.Add("client_id", context.Options.ClientId);

    return Task.CompletedTask;
  }
}
