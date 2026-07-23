namespace MonoCloud.Authentication.Api.Shared.ClientAuth;

/// <summary>
/// Represents the SPIFFE JWT-SVID based client authentication mechanism ('spiffe_jwt').
/// The workload's JWT-SVID is forwarded as the client assertion on introspection requests,
/// using the 'urn:ietf:params:oauth:client-assertion-type:jwt-spiffe' assertion type.
/// </summary>
/// <remarks>
/// JWT-SVIDs are short-lived. Prefer the provider based constructor
/// (<see cref="SpiffeJwtAuth(Func{HttpContext, CancellationToken, Task{string}})"/>) with a delegate
/// that returns the current SVID (e.g. from the SPIFFE Workload API), so rotated SVIDs are picked up
/// without restarting the application. The delegate receives the current <see cref="HttpContext"/>,
/// so it can resolve services from <see cref="HttpContext.RequestServices"/> (e.g. a Workload API client).
/// </remarks>
public class SpiffeJwtAuth : IMonoCloudClientAuth
{
  private const string SpiffeJwtAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe";

  private readonly Func<HttpContext, CancellationToken, Task<string>> _jwtSvidProvider;

  /// <summary>
  /// Spiffe jwt authentication with a fixed JWT-SVID.
  /// </summary>
  /// <param name="jwtSvid">The SPIFFE JWT-SVID (obtained from the SPIFFE Workload API)</param>
  public SpiffeJwtAuth(string jwtSvid)
  {
    _jwtSvidProvider = (_, _) => Task.FromResult(jwtSvid);
  }

  /// <summary>
  /// Spiffe jwt authentication with a JWT-SVID provider that is invoked for each introspection request.
  /// The provider receives the current <see cref="HttpContext"/>, allowing it to resolve services from
  /// <see cref="HttpContext.RequestServices"/> (e.g. a SPIFFE Workload API client).
  /// </summary>
  /// <param name="jwtSvidProvider">A delegate returning the current SPIFFE JWT-SVID</param>
  public SpiffeJwtAuth(Func<HttpContext, CancellationToken, Task<string>> jwtSvidProvider)
  {
    _jwtSvidProvider = jwtSvidProvider;
  }

  /// <inheritdoc />
  public async Task AuthenticateAsync(ClientAuthenticationContext context, CancellationToken cancellationToken)
  {
    if (string.IsNullOrEmpty(context.Options.ClientId))
    {
      throw new ArgumentNullException(nameof(context.Options.ClientId), "ClientId must be set");
    }

    var jwtSvid = await _jwtSvidProvider(context.HttpContext, cancellationToken);

    if (string.IsNullOrEmpty(jwtSvid))
    {
      throw new InvalidOperationException("The SPIFFE JWT-SVID must not be null or empty");
    }

    context.IntrospectionRequestPayload.Add("client_id", context.Options.ClientId);
    context.IntrospectionRequestPayload.Add("client_assertion_type", SpiffeJwtAssertionType);
    context.IntrospectionRequestPayload.Add("client_assertion", jwtSvid);
  }
}
