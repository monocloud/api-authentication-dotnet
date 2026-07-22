namespace MonoCloud.Authentication.Api.Tests.Helpers;

/// <summary>
/// Builds a fully initialized <see cref="MonoCloudAuthenticationHandler"/> over a <see cref="DefaultHttpContext"/>,
/// running the same <see cref="PostConfigureMonoCloudAuthenticationOptions"/> step the framework applies in production.
/// </summary>
public static class HandlerTestHarness
{
  public const string Scheme = MonoCloudAuthenticationDefaults.AuthenticationScheme;

  public static async Task<(MonoCloudAuthenticationHandler Handler, DefaultHttpContext Context)> CreateAsync(
      MonoCloudAuthenticationOptions options,
      string? token = null,
      IIntrospectionCache? cache = null,
      X509Certificate2? clientCertificate = null,
      string scheme = Scheme)
  {
    new PostConfigureMonoCloudAuthenticationOptions(new HttpClientFactoryMock(), cache).PostConfigure(scheme, options);

    var context = new DefaultHttpContext();

    if (token is not null)
    {
      context.Request.Headers["Authorization"] = $"Bearer {token}";
    }

    if (clientCertificate is not null)
    {
      context.Connection.ClientCertificate = clientCertificate;
    }

    var monitor = new MonoCloudAuthenticationOptionMonitorMock(options);

    var handler = new MonoCloudAuthenticationHandler(monitor, UrlEncoder.Default, NullLoggerFactory.Instance, cache: cache);

    var authScheme = new AuthenticationScheme(scheme, scheme, typeof(MonoCloudAuthenticationHandler));

    await handler.InitializeAsync(authScheme, context);

    return (handler, context);
  }
}
