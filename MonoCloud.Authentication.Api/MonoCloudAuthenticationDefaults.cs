namespace MonoCloud.Authentication.Api;

/// <summary>
/// Default values used by the SDK
/// </summary>
public static class MonoCloudAuthenticationDefaults
{
  /// <summary>
  /// Default authentication scheme
  /// </summary>
  public const string AuthenticationScheme = "MonoCloud";

  /// <summary>
  /// Http client name used by the sdk to create http clients from the <see cref="IHttpClientFactory"/>.
  /// </summary>
  public const string HttpClientName = "MonoCloud.AspNetCore.HttpClient";
}
