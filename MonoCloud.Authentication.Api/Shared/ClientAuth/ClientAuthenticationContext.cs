namespace MonoCloud.Authentication.Api.Shared.ClientAuth;

/// <summary>
/// Represents the context for <see cref="IMonoCloudClientAuth"/>.
/// This context encapsulates all relevant details and state for performing client authentication,
/// including the authentication options, request message, payload, HTTP context, and scheme.
/// </summary>
public class ClientAuthenticationContext
{
  /// <summary>
  /// MonoCloud authentication options of the current scheme.
  /// </summary>
  public readonly MonoCloudAuthenticationOptions Options;

  /// <summary>
  /// Represents the HTTP request message used for token introspection.
  /// </summary>
  public readonly HttpRequestMessage IntrospectionRequest;

  /// <summary>
  /// Represents the payload of a token introspection request as a collection of key-value pairs.
  /// This dictionary is used to include additional parameters or credentials required for client authentication during introspection.
  /// </summary>
  public readonly IDictionary<string, string> IntrospectionRequestPayload;

  /// <summary>
  /// HTTP context of the current request within the client authentication process.
  /// </summary>
  public readonly HttpContext HttpContext;

  /// <summary>
  /// The authentication scheme used in the current client authentication process.
  /// </summary>
  public readonly AuthenticationScheme Scheme;

  /// <summary>
  /// Represents the context for <see cref="IMonoCloudClientAuth"/>.
  /// This context encapsulates all relevant details and state for performing client authentication,
  /// including the authentication options, request message, payload, HTTP context, and scheme.
  /// </summary>
  public ClientAuthenticationContext(MonoCloudAuthenticationOptions options,
    HttpRequestMessage introspectionRequest,
    IDictionary<string, string> introspectionRequestPayload,
    HttpContext httpContext,
    AuthenticationScheme scheme)
  {
    Options = options;
    IntrospectionRequest = introspectionRequest;
    IntrospectionRequestPayload = introspectionRequestPayload;
    HttpContext = httpContext;
    Scheme = scheme;
  }
}
