namespace MonoCloud.Authentication.Api.Tests;

public class JwtBearerDelegationTests
{
  private const string OpaqueToken = "opaque-access-token";

  private static MonoCloudAuthenticationOptions JwtOptions(OpenIdServerMock server, Action<MonoCloudAuthenticationOptions>? configure = null)
  {
    server.SetupDiscovery();
    server.SetupJwks();

    var options = new MonoCloudAuthenticationOptions
    {
      Authority = OpenIdServerMock.Issuer,
      Audience = OpenIdServerMock.Issuer,
      MapInboundClaims = false,
      HttpClient = server.Build()
    };

    configure?.Invoke(options);

    return options;
  }

  private static MonoCloudAuthenticationOptions OpaqueOptions(OpenIdServerMock server, Action<MonoCloudAuthenticationOptions>? configure = null)
  {
    server.SetupDiscovery();
    server.SetupJwks();
    server.SetupIntrospection(authType: "client_secret_post");

    var options = new MonoCloudAuthenticationOptions
    {
      Authority = OpenIdServerMock.Issuer,
      ClientId = OpenIdServerMock.ClientId,
      ClientAuth = new ClientSecretAuth(OpenIdServerMock.SymmetricSecret),
      HttpClient = server.Build()
    };

    configure?.Invoke(options);

    return options;
  }

  private static long Unix(DateTime dt) => new DateTimeOffset(dt.ToUniversalTime()).ToUnixTimeSeconds();

  private static string ExpiredToken() => OpenIdServerMock.CreateAccessToken(new List<Claim>
  {
    new("iat", Unix(DateTime.UtcNow.AddMinutes(-30)).ToString()),
    new("nbf", Unix(DateTime.UtcNow.AddMinutes(-30)).ToString()),
    new("exp", Unix(DateTime.UtcNow.AddMinutes(-20)).ToString())
  });

  [Test]
  public async Task MessageReceived_IsRaisedExactlyOnce_OnTheJwtPath()
  {
    var invocations = 0;

    var options = JwtOptions(new OpenIdServerMock(), o => o.Events.OnMessageReceived = _ =>
    {
      invocations++;
      return Task.CompletedTask;
    });

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpenIdServerMock.CreateAccessToken());
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
    invocations.ShouldBe(1);
  }

  [Test]
  public async Task MessageReceived_IsRaisedExactlyOnce_OnTheOpaquePath()
  {
    var invocations = 0;

    var options = OpaqueOptions(new OpenIdServerMock(), o => o.Events.OnMessageReceived = _ =>
    {
      invocations++;
      return Task.CompletedTask;
    });

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
    invocations.ShouldBe(1);
  }

  [Test]
  public async Task Should_Authenticate_When_JwtIsSuppliedOnlyByMessageReceived()
  {
    var token = OpenIdServerMock.CreateAccessToken();

    var options = JwtOptions(new OpenIdServerMock(), o => o.Events.OnMessageReceived = context =>
    {
      context.Token = token;
      return Task.CompletedTask;
    });

    var (handler, _) = await HandlerTestHarness.CreateAsync(options);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
    result.Principal!.FindFirst("sub")!.Value.ShouldBe("1234567890");
  }

  [Test]
  public async Task Should_Introspect_When_OpaqueTokenIsSuppliedOnlyByMessageReceived()
  {
    var server = new OpenIdServerMock();

    var options = OpaqueOptions(server, o => o.Events.OnMessageReceived = context =>
    {
      context.Token = OpaqueToken;
      return Task.CompletedTask;
    });

    var (handler, _) = await HandlerTestHarness.CreateAsync(options);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
    server.VerifyIntrospectionCalled();
  }

  [Test]
  public async Task Should_ShortCircuit_When_MessageReceivedSetsAResult()
  {
    var server = new OpenIdServerMock();

    var options = JwtOptions(server, o => o.Events.OnMessageReceived = context =>
    {
      context.Fail("rejected by the consumer");
      return Task.CompletedTask;
    });

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpenIdServerMock.CreateAccessToken());
    var result = await handler.AuthenticateAsync();

    result.Failure!.Message.ShouldBe("rejected by the consumer");
    server.VerifyJwksCalled(Times.Never());
  }

  [Test]
  public async Task TokenValidated_ReceivesTheValidatedSecurityToken_OnTheJwtPath()
  {
    SecurityToken? securityToken = null;

    var options = JwtOptions(new OpenIdServerMock(), o => o.Events.OnTokenValidated = context =>
    {
      securityToken = context.SecurityToken;
      return Task.CompletedTask;
    });

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpenIdServerMock.CreateAccessToken());
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
    securityToken.ShouldBeOfType<JsonWebToken>();
  }

  [Test]
  public async Task Challenge_EmitsBearerErrorDetails_When_AuthenticationFailed()
  {
    var options = JwtOptions(new OpenIdServerMock());

    var (handler, context) = await HandlerTestHarness.CreateAsync(options, ExpiredToken());

    await handler.ChallengeAsync(null);

    context.Response.StatusCode.ShouldBe(401);

    var challenge = context.Response.Headers.WWWAuthenticate.ToString();
    challenge.ShouldStartWith("Bearer");
    challenge.ShouldContain("error=\"invalid_token\"");
    challenge.ShouldContain("error_description=");
  }

  [Test]
  public async Task Challenge_OmitsErrorDetails_When_IncludeErrorDetailsIsDisabled()
  {
    var options = JwtOptions(new OpenIdServerMock(), o => o.IncludeErrorDetails = false);

    var (handler, context) = await HandlerTestHarness.CreateAsync(options, ExpiredToken());

    await handler.ChallengeAsync(null);

    context.Response.StatusCode.ShouldBe(401);
    context.Response.Headers.WWWAuthenticate.ToString().ShouldBe("Bearer");
  }

  [Test]
  public async Task Challenge_IsSuppressible_ThroughTheChallengeEvent()
  {
    var options = JwtOptions(new OpenIdServerMock(), o => o.Events.OnChallenge = context =>
    {
      context.HandleResponse();
      return Task.CompletedTask;
    });

    var (handler, context) = await HandlerTestHarness.CreateAsync(options);

    await handler.ChallengeAsync(null);

    context.Response.StatusCode.ShouldBe(200);
    context.Response.Headers.WWWAuthenticate.ToString().ShouldBeEmpty();
  }

  [Test]
  public async Task Forbid_RaisesTheForbiddenEvent()
  {
    var forbidden = false;

    var options = JwtOptions(new OpenIdServerMock(), o => o.Events.OnForbidden = _ =>
    {
      forbidden = true;
      return Task.CompletedTask;
    });

    var (handler, context) = await HandlerTestHarness.CreateAsync(options);

    await handler.ForbidAsync(null);

    context.Response.StatusCode.ShouldBe(403);
    forbidden.ShouldBeTrue();
  }
}
