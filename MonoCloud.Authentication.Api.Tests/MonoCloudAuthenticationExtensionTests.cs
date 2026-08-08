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

    var scheme = await sp.GetRequiredService<IAuthenticationSchemeProvider>().GetSchemeAsync(MonoCloudAuthenticationDefaults.AuthenticationScheme);

    scheme.ShouldNotBeNull();
    scheme!.HandlerType.ShouldBe(typeof(MonoCloudAuthenticationHandler));
  }

  [Test]
  public void Should_RegisterPostConfigureOptions()
  {
    var sp = BuildProvider(b => b.AddMonoCloudAuthentication());

    sp.GetServices<IPostConfigureOptions<MonoCloudAuthenticationOptions>>().ShouldContain(x => x is PostConfigureMonoCloudAuthenticationOptions);
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

    var options = sp.GetRequiredService<IOptionsMonitor<MonoCloudAuthenticationOptions>>().Get(MonoCloudAuthenticationDefaults.AuthenticationScheme);

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

  [Test]
  public void Should_ResolveHandlerFromTheContainer()
  {
    var sp = BuildProvider(b => b.AddMonoCloudAuthentication());

    sp.GetService<MonoCloudAuthenticationHandler>().ShouldNotBeNull();
  }

  [Test]
  public void Should_ResolveTheUnnamedOptionsInstance()
  {
    var sp = BuildProvider(b => b.AddMonoCloudAuthentication());

    Should.NotThrow(() => sp.GetRequiredService<IOptions<MonoCloudAuthenticationOptions>>().Value);
    Should.NotThrow(() => sp.GetRequiredService<IOptionsMonitor<MonoCloudAuthenticationOptions>>().CurrentValue);
  }

  [Test]
  public void Should_RegisterTimeProviderPostConfigure()
  {
    var sp = BuildProvider(b => b.AddMonoCloudAuthentication());

    var options = sp.GetRequiredService<IOptionsMonitor<MonoCloudAuthenticationOptions>>().Get(MonoCloudAuthenticationDefaults.AuthenticationScheme);

    options.TimeProvider.ShouldNotBeNull();
  }

  [Test]
  public void Should_RegisterEachPostConfigureOnce_When_MultipleSchemesAreAdded()
  {
    var sp = BuildProvider(b => b
      .AddMonoCloudAuthentication("scheme-one")
      .AddMonoCloudAuthentication("scheme-two"));

    var postConfigures = sp.GetServices<IPostConfigureOptions<MonoCloudAuthenticationOptions>>().ToList();

    postConfigures.Count(x => x is PostConfigureMonoCloudAuthenticationOptions).ShouldBe(1);
  }

  [Test]
  public async Task Should_Throw_When_TheSameSchemeIsRegisteredTwice()
  {
    var sp = BuildProvider(b => b
      .AddMonoCloudAuthentication()
      .AddMonoCloudAuthentication());

    var exception = await Should.ThrowAsync<InvalidOperationException>(
      () => sp.GetRequiredService<IAuthenticationSchemeProvider>().GetSchemeAsync(MonoCloudAuthenticationDefaults.AuthenticationScheme));

    exception.Message.ShouldContain("Scheme already exists");
  }
}
