namespace MonoCloud.Authentication.Api;

/// <inheritdoc />
public class PostConfigureMonoCloudAuthenticationOptions : IPostConfigureOptions<MonoCloudAuthenticationOptions>
{
  private readonly IHttpClientFactory _httpClientFactory;
  private readonly IIntrospectionCache? _cache;

  /// <summary>
  /// <see cref="PostConfigureMonoCloudAuthenticationOptions"/>
  /// </summary>
  /// <param name="httpClientFactory"></param>
  /// <param name="cache"></param>
  public PostConfigureMonoCloudAuthenticationOptions(IHttpClientFactory httpClientFactory, IIntrospectionCache? cache = null)
  {
    _httpClientFactory = httpClientFactory;
    _cache = cache;
  }

  /// <inheritdoc />
  public void PostConfigure(string? name, MonoCloudAuthenticationOptions options)
  {
    options.SchemeName = name;

    if (options.EnableCaching && _cache == null)
    {
      throw new ArgumentException("IIntrospectionCache not found in the services collection", nameof(_cache));
    }

    if (options.TenantDomain is not null && !options.TenantDomain.StartsWith("https://"))
    {
      options.TenantDomain = $"https://{options.TenantDomain}";
    }

    if (string.IsNullOrEmpty(options.JwtTokenValidationParameters.ValidAudience) && !string.IsNullOrEmpty(options.Audience))
    {
      options.JwtTokenValidationParameters.ValidAudience = options.Audience;
    }

    // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
    if (options.HttpClient == null)
    {
      if (options.ClientAuth is TlsAuth tlsAuth && tlsAuth.Certificate is not null)
      {
        var handler = new HttpClientHandler();

        handler.ClientCertificates.Add(tlsAuth.Certificate);

        options.HttpClient = new HttpClient(handler);
      }
      else
      {
        options.HttpClient = _httpClientFactory.CreateClient(MonoCloudAuthenticationDefaults.HttpClientName);
      }
    }

    if (options.ConfigurationManager is null)
    {
      if (options.Configuration != null)
      {
        options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(options.Configuration);
      }
      else if (options.TenantDomain is not null)
      {
        var discoveryUrl = options.TenantDomain;

        if (!discoveryUrl.EndsWith("/", StringComparison.Ordinal))
        {
          discoveryUrl += "/";
        }

        discoveryUrl += ".well-known/openid-configuration";

        options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(discoveryUrl, new OpenIdConnectConfigurationRetriever(), new HttpDocumentRetriever(options.HttpClient))
        {
          RefreshInterval = options.RefreshInterval,
          AutomaticRefreshInterval = options.AutomaticRefreshInterval,
        };
      }
    }
  }
}
