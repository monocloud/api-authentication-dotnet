namespace MonoCloud.Authentication.Api.Tests;

public class MonoCloudAuthenticationEventsTests
{
  private static readonly AuthenticationScheme TestScheme = new("MonoCloud", "MonoCloud", typeof(MonoCloudAuthenticationHandler));
  private static readonly HttpContext HttpContext = new DefaultHttpContext();
  private static readonly MonoCloudAuthenticationOptions Opts = new();

  [Test]
  public async Task Defaults_AreNoOps_AndDoNotThrow()
  {
    var events = new MonoCloudAuthenticationEvents();

    await Should.NotThrowAsync(async () =>
    {
      await events.MessageReceived(new MessageReceivedContext(HttpContext, TestScheme, Opts));
      await events.TokenValidated(new TokenValidatedContext(HttpContext, TestScheme, Opts));
      await events.AuthenticationFailed(new AuthenticationFailedContext(HttpContext, TestScheme, Opts));
      await events.Introspection(new IntrospectionRequestContext(HttpContext, TestScheme, Opts));
      await events.CreatingJwtAssertion(new JwtAssertionContext(HttpContext, TestScheme, Opts));
      await events.CertificateBindingValidated(new CertificateBindingValidatedContext(HttpContext, TestScheme, Opts));
    });
  }

  [Test]
  public async Task MessageReceived_InvokesHandler()
  {
    var invoked = false;
    var events = new MonoCloudAuthenticationEvents { OnMessageReceived = _ => { invoked = true; return Task.CompletedTask; } };

    await events.MessageReceived(new MessageReceivedContext(HttpContext, TestScheme, Opts));

    invoked.ShouldBeTrue();
  }

  [Test]
  public async Task TokenValidated_InvokesHandler()
  {
    var invoked = false;
    var events = new MonoCloudAuthenticationEvents { OnTokenValidated = _ => { invoked = true; return Task.CompletedTask; } };

    await events.TokenValidated(new TokenValidatedContext(HttpContext, TestScheme, Opts));

    invoked.ShouldBeTrue();
  }

  [Test]
  public async Task AuthenticationFailed_InvokesHandler()
  {
    var invoked = false;
    var events = new MonoCloudAuthenticationEvents { OnAuthenticationFailed = _ => { invoked = true; return Task.CompletedTask; } };

    await events.AuthenticationFailed(new AuthenticationFailedContext(HttpContext, TestScheme, Opts));

    invoked.ShouldBeTrue();
  }

  [Test]
  public async Task Introspection_InvokesHandler()
  {
    var invoked = false;
    var events = new MonoCloudAuthenticationEvents { OnIntrospection = _ => { invoked = true; return Task.CompletedTask; } };

    await events.Introspection(new IntrospectionRequestContext(HttpContext, TestScheme, Opts));

    invoked.ShouldBeTrue();
  }

  [Test]
  public async Task CreatingJwtAssertion_InvokesHandler()
  {
    var invoked = false;
    var events = new MonoCloudAuthenticationEvents { OnCreatingJwtAssertion = _ => { invoked = true; return Task.CompletedTask; } };

    await events.CreatingJwtAssertion(new JwtAssertionContext(HttpContext, TestScheme, Opts));

    invoked.ShouldBeTrue();
  }

  [Test]
  public async Task CertificateBindingValidated_InvokesHandler()
  {
    var invoked = false;
    var events = new MonoCloudAuthenticationEvents { OnCertificateBindingValidated = _ => { invoked = true; return Task.CompletedTask; } };

    await events.CertificateBindingValidated(new CertificateBindingValidatedContext(HttpContext, TestScheme, Opts));

    invoked.ShouldBeTrue();
  }
}
