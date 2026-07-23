namespace MonoCloud.Authentication.Api.Tests;

public class PostConfigureTests
{
  private static X509CertificateCollection ClientCertificatesOf(HttpClient client)
  {
    var handler = (HttpClientHandler)typeof(HttpMessageInvoker).GetField("_handler", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(client)!;

    return handler.ClientCertificates;
  }

  [Test]
  public void Should_ThrowArgumentException_When_CachingIsEnabledWithoutCache()
  {
    var postConfigureOptions = new PostConfigureMonoCloudAuthenticationOptions(null!);

    var options = new MonoCloudAuthenticationOptions
    {
      EnableCaching = true
    };

    Should.Throw<ArgumentException>(() => postConfigureOptions.PostConfigure(null, options)).Message.ShouldBe("IIntrospectionCache not found in the services collection (Parameter '_cache')");
  }

  [Test]
  public void Should_PrependHttps_When_DomainHasNoProtocol()
  {
    var options = new MonoCloudAuthenticationOptions
    {
      TenantDomain = "example.com"
    };

    var postConfigureOptions = new PostConfigureMonoCloudAuthenticationOptions(new HttpClientFactoryMock());
    postConfigureOptions.PostConfigure(null, options);

    options.TenantDomain.ShouldBe("https://example.com");
  }

  [Test]
  public void Should_NotPrependHttps_When_DomainAlreadyHasHttps()
  {
    var options = new MonoCloudAuthenticationOptions
    {
      TenantDomain = "https://example.com",
    };

    var postConfigureOptions = new PostConfigureMonoCloudAuthenticationOptions(new HttpClientFactoryMock());
    postConfigureOptions.PostConfigure(null, options);

    options.TenantDomain.ShouldBe("https://example.com");
  }

  [Test]
  public async Task Should_UseStaticConfigurationManager_When_ConfigurationIsProvided()
  {
    var options = new MonoCloudAuthenticationOptions
    {
      ConfigurationManager = null,
      Configuration = new OpenIdConnectConfiguration
      {
        Issuer = "https://tester.com"
      }
    };

    var postConfigureOptions = new PostConfigureMonoCloudAuthenticationOptions(new HttpClientFactoryMock());
    postConfigureOptions.PostConfigure(null, options);

    options.ConfigurationManager.ShouldBeOfType<StaticConfigurationManager<OpenIdConnectConfiguration>>();

    var config = await options.ConfigurationManager.GetConfigurationAsync(CancellationToken.None);
    config.ShouldBe(options.Configuration);
  }

  [Test]
  public void Should_UseConfigurationManager_When_TenantDomainIsProvided()
  {
    var options = new MonoCloudAuthenticationOptions
    {
      TenantDomain = "example.com",
      ConfigurationManager = null,
      Configuration = null
    };

    var postConfigureOptions = new PostConfigureMonoCloudAuthenticationOptions(new HttpClientFactoryMock());
    postConfigureOptions.PostConfigure(null, options);

    options.ConfigurationManager.ShouldBeOfType<ConfigurationManager<OpenIdConnectConfiguration>>();
  }

  [Test]
  public void Should_SetValidAudience_When_AudienceIsConfigured()
  {
    var options = new MonoCloudAuthenticationOptions
    {
      Audience = "https://api.example.com",
    };

    var postConfigureOptions = new PostConfigureMonoCloudAuthenticationOptions(new HttpClientFactoryMock());
    postConfigureOptions.PostConfigure(null, options);

    options.JwtTokenValidationParameters.ValidAudience.ShouldBe(options.Audience);
  }

  [Test]
  public void PostConfigure_ShouldNotOverwrite_WhenValidAudienceIsAlreadySet()
  {
    var options = new MonoCloudAuthenticationOptions
    {
      Audience = "new-audience",
      JwtTokenValidationParameters = new TokenValidationParameters
      {
        ValidAudience = "existing-audience"
      }
    };

    var postConfigureOptions = new PostConfigureMonoCloudAuthenticationOptions(new HttpClientFactoryMock());
    postConfigureOptions.PostConfigure(null, options);

    options.JwtTokenValidationParameters.ValidAudience.ShouldBe("existing-audience");
  }

  [Test]
  public void Should_CreateHttpClientWithCertificate_When_TlsAuthIsConfiguredAndNoClientProvided()
  {
    var options = new MonoCloudAuthenticationOptions
    {
      HttpClient = null!,
      ClientAuth = new TlsAuth(OpenIdServerMock.MtlsClientCert)
    };

    var postConfigureOptions = new PostConfigureMonoCloudAuthenticationOptions(null!);
    postConfigureOptions.PostConfigure(null, options);

    var certificates = ClientCertificatesOf(options.HttpClient);
    certificates.Count.ShouldBe(1);
    certificates[0].ShouldBe(OpenIdServerMock.MtlsClientCert);
  }

  [Test]
  public void Should_CreateHttpClientWithCertificate_When_SpiffeX509AuthIsConfiguredAndNoClientProvided()
  {
    var options = new MonoCloudAuthenticationOptions
    {
      HttpClient = null!,
      ClientAuth = new SpiffeX509Auth(OpenIdServerMock.PrivateKeyCert)
    };

    var postConfigureOptions = new PostConfigureMonoCloudAuthenticationOptions(null!);
    postConfigureOptions.PostConfigure(null, options);

    var certificates = ClientCertificatesOf(options.HttpClient);
    certificates.Count.ShouldBe(1);
    certificates[0].ShouldBe(OpenIdServerMock.PrivateKeyCert);
  }

  [Test]
  public void Should_CreateHttpClient_When_NoHttpClientIsProvided()
  {
    var options = new MonoCloudAuthenticationOptions
    {
      HttpClient = null!
    };

    var postConfigureOptions = new PostConfigureMonoCloudAuthenticationOptions(new HttpClientFactoryMock(), null);
    postConfigureOptions.PostConfigure(null, options);

    options.HttpClient.ShouldBeOfType<HttpClient>();
  }
}
