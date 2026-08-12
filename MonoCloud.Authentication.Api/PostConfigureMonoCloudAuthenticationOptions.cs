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

    if (options.Authority is not null && !options.Authority.Contains("://"))
    {
      options.Authority = $"https://{options.Authority}";
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

    options.Backchannel ??= options.HttpClient;

    var authenticationType = options.AuthenticationType ?? name;

    if (options.TokenValidationParameters.AuthenticationType is null && !string.IsNullOrWhiteSpace(authenticationType))
    {
      options.TokenValidationParameters.AuthenticationType = authenticationType;
    }

    if (options.NameClaimType is not null)
    {
      options.TokenValidationParameters.NameClaimType = options.NameClaimType;
    }

    if (options.RoleClaimType is not null)
    {
      options.TokenValidationParameters.RoleClaimType = options.RoleClaimType;
    }

    if (options.ClockSkew.HasValue)
    {
      options.TokenValidationParameters.ClockSkew = options.ClockSkew.Value;
    }

    new JwtBearerPostConfigureOptions().PostConfigure(name, options);
  }
}
