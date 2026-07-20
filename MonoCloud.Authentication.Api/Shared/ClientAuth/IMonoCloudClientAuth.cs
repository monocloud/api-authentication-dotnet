namespace MonoCloud.Authentication.Api.Shared.ClientAuth;

/// <summary>
/// Defines the contract for MonoCloud client authentication mechanisms.
/// Implementing this interface allows custom authentication schemes
/// to be integrated into the authentication process for securing client access.
/// </summary>
public interface IMonoCloudClientAuth
{
  /// <summary>
  /// Attempts to authenticate a client using the provided authentication context and token.
  /// </summary>
  /// <param name="context">The context of the client authentication, including options, HTTP request, payload, and scheme details.</param>
  /// <param name="cancellationToken">A cancellation token for controlling the asynchronous operation.</param>
  /// <returns>A task that represents the asynchronous operation.</returns>
  Task AuthenticateAsync(ClientAuthenticationContext context, CancellationToken cancellationToken);
}
