namespace MonoCloud.Authentication.Api.Tests;

public class MonoCloudAuthenticationExtensionTests
{
  private static ServiceProvider BuildProvider(Action<AuthenticationBuilder> register)
  {
    var services = new ServiceCollection();
    services.AddLogging();
    register(services.AddAuthentication());
    return services.BuildServiceProvider();
  }

  [Test]
  public async Task Should_RegisterDefaultScheme_WithHandler()
  {
    var sp = BuildProvider(b => b.AddMonoCloudAuthentication());

    var scheme = await sp.GetRequiredService<IAuthenticationSchemeProvider>()
        .GetSchemeAsync(MonoCloudAuthenticationDefaults.AuthenticationScheme);

    scheme.ShouldNotBeNull();
    scheme!.HandlerType.ShouldBe(typeof(MonoCloudAuthenticationHandler));
  }

  [Test]
  public void Should_RegisterPostConfigureOptions()
  {
    var sp = BuildProvider(b => b.AddMonoCloudAuthentication());

    sp.GetServices<IPostConfigureOptions<MonoCloudAuthenticationOptions>>()
        .ShouldContain(x => x is PostConfigureMonoCloudAuthenticationOptions);
  }

  [Test]
  public void Should_RegisterHttpClientFactory()
  {
    var sp = BuildProvider(b => b.AddMonoCloudAuthentication());

    sp.GetService<IHttpClientFactory>().ShouldNotBeNull();
  }

  [Test]
  public void Should_ApplyConfigureOptions_ToDefaultScheme()
  {
    var sp = BuildProvider(b => b.AddMonoCloudAuthentication(o => o.ClientId = "configured-client"));

    var options = sp.GetRequiredService<IOptionsMonitor<MonoCloudAuthenticationOptions>>()
        .Get(MonoCloudAuthenticationDefaults.AuthenticationScheme);

    options.ClientId.ShouldBe("configured-client");
  }

  [Test]
  public async Task Should_RegisterCustomScheme_WithConfiguredOptions()
  {
    var sp = BuildProvider(b => b.AddMonoCloudAuthentication("custom-scheme", o => o.ClientId = "custom-client"));

    var scheme = await sp.GetRequiredService<IAuthenticationSchemeProvider>().GetSchemeAsync("custom-scheme");
    scheme.ShouldNotBeNull();

    var options = sp.GetRequiredService<IOptionsMonitor<MonoCloudAuthenticationOptions>>().Get("custom-scheme");
    options.ClientId.ShouldBe("custom-client");
  }
}
