namespace MonoCloud.Authentication.Api.Shared.ClientAuth;

/// <summary>
/// Represents a client secret authentication mechanism used for securing
/// access by attaching the client ID and client secret to the requests.
/// </summary>
/// <remarks>
/// Represents the client secret-based authentication mechanism for MonoCloud client.
/// </remarks>
public class ClientSecretAuth : IMonoCloudClientAuth
{
  private readonly bool _clientSecretBasic;

  /// <summary>
  /// Represents a client secret authentication mechanism used for securing
  /// access by attaching the client ID and client secret to the requests.
  /// </summary>
  /// <remarks>
  /// Represents the client secret-based authentication mechanism for MonoCloud client.
  /// </remarks>
  /// <param name="clientSecret">The client secret</param>
  /// <param name="clientSecretBasic">Specifies whether to use client_secret_basic authentication</param>
  public ClientSecretAuth(string clientSecret, bool clientSecretBasic = false)
  {
    _clientSecretBasic = clientSecretBasic;
    ClientSecret = clientSecret;
  }

  private string ClientSecret { get; }

  /// <inheritdoc />
  public Task AuthenticateAsync(ClientAuthenticationContext context, CancellationToken cancellationToken)
  {
    if (string.IsNullOrEmpty(context.Options.ClientId))
    {
      throw new ArgumentNullException(nameof(context.Options.ClientId), "ClientId must be set");
    }

    if (_clientSecretBasic)
    {
      var headerValue = $"Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Uri.EscapeDataString(context.Options.ClientId)}:{Uri.EscapeDataString(ClientSecret)}"))}";
      context.IntrospectionRequest.Headers.Add("Authorization", headerValue);
    }
    else
    {
      context.IntrospectionRequestPayload.Add("client_id", context.Options.ClientId);
      context.IntrospectionRequestPayload.Add("client_secret", ClientSecret);
    }

    return Task.CompletedTask;
  }

}
