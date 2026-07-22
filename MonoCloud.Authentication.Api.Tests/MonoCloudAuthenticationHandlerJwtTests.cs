namespace MonoCloud.Authentication.Api.Tests;

public class MonoCloudAuthenticationHandlerJwtTests
{
  private static MonoCloudAuthenticationOptions JwtOptions(OpenIdServerMock server, Action<MonoCloudAuthenticationOptions>? configure = null)
  {
    server.SetupDiscovery();
    server.SetupJwks();

    var options = new MonoCloudAuthenticationOptions
    {
      TenantDomain = OpenIdServerMock.Issuer,
      Audience = OpenIdServerMock.Issuer,
      MapInboundClaims = false,
      HttpClient = server.Build()
    };

    configure?.Invoke(options);

    return options;
  }

  private static long Unix(DateTime dt) => new DateTimeOffset(dt.ToUniversalTime()).ToUnixTimeSeconds();

  [Test]
  public async Task Should_Authenticate_When_JwtIsValid()
  {
    var options = JwtOptions(new OpenIdServerMock());
    var token = OpenIdServerMock.CreateAccessToken();

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, token);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
    result.Principal.ShouldNotBeNull();
    result.Principal!.FindFirst("sub")!.Value.ShouldBe("1234567890");
    result.Principal!.FindFirst("client_id")!.Value.ShouldBe(OpenIdServerMock.ClientId);
    result.Ticket!.AuthenticationScheme.ShouldBe(HandlerTestHarness.Scheme);
  }

  [Test]
  public async Task Should_Fail_When_TokenIsMissing()
  {
    var options = JwtOptions(new OpenIdServerMock());

    var (handler, _) = await HandlerTestHarness.CreateAsync(options);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeFalse();
    result.Failure!.Message.ShouldBe("Missing Token");
  }

  [Test]
  public async Task Should_Fail_When_AuthorizationHeaderIsNotBearer()
  {
    var options = JwtOptions(new OpenIdServerMock());

    var (handler, context) = await HandlerTestHarness.CreateAsync(options);
    context.Request.Headers["Authorization"] = "Basic Zm9vOmJhcg==";

    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeFalse();
    result.Failure!.Message.ShouldBe("Missing Token");
  }

  [Test]
  public async Task Should_ReadToken_When_HeaderUsesLowercaseBearer()
  {
    var options = JwtOptions(new OpenIdServerMock());
    var token = OpenIdServerMock.CreateAccessToken();

    var (handler, context) = await HandlerTestHarness.CreateAsync(options);
    context.Request.Headers["Authorization"] = $"bearer {token}";

    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue();
  }

  [Test]
  public async Task Should_Fail_When_SignatureIsInvalid()
  {
    var options = JwtOptions(new OpenIdServerMock());
    var token = OpenIdServerMock.CreateAccessToken();
    // Tamper the signature segment.
    var tampered = token[..^3] + (token.EndsWith("AAA") ? "BBB" : "AAA");

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, tampered);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeFalse();
  }

  [Test]
  public async Task Should_Fail_When_TokenIsExpired()
  {
    var options = JwtOptions(new OpenIdServerMock());
    var past = DateTime.UtcNow.AddMinutes(-30);
    var token = OpenIdServerMock.CreateAccessToken(new List<Claim>
        {
            new("iat", Unix(past).ToString()),
            new("nbf", Unix(past).ToString()),
            new("exp", Unix(DateTime.UtcNow.AddMinutes(-20)).ToString())
        });

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, token);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeFalse();
  }

  [Test]
  public async Task Should_Fail_When_AudienceDoesNotMatch()
  {
    var options = JwtOptions(new OpenIdServerMock(), o => o.Audience = "https://not-the-right-audience");
    var token = OpenIdServerMock.CreateAccessToken();

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, token);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeFalse();
  }

  [Test]
  public async Task Should_StoreAccessToken_When_SaveTokenIsEnabled()
  {
    var options = JwtOptions(new OpenIdServerMock(), o => o.SaveToken = true);
    var token = OpenIdServerMock.CreateAccessToken();

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, token);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue();
    result.Properties!.GetTokenValue("access_token").ShouldBe(token);
  }

  [Test]
  public async Task Should_NotStoreAccessToken_When_SaveTokenIsDisabled()
  {
    var options = JwtOptions(new OpenIdServerMock());
    var token = OpenIdServerMock.CreateAccessToken();

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, token);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue();
    result.Properties!.GetTokenValue("access_token").ShouldBeNull();
  }

  [Test]
  public async Task Should_UseNameClaimType_When_Configured()
  {
    var options = JwtOptions(new OpenIdServerMock(), o => o.NameClaimType = "sub");
    var token = OpenIdServerMock.CreateAccessToken();

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, token);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue();
    result.Principal!.Identity!.Name.ShouldBe("1234567890");
  }

  [Test]
  public async Task Should_NormalizeGroupClaims_When_RoleClaimTypeIsAGroupArray()
  {
    var options = JwtOptions(new OpenIdServerMock(), o => o.RoleClaimType = "groups");
    // A real JSON-array `groups` claim so the handler can normalize it.
    var token = OpenIdServerMock.CreateAccessToken(new List<Claim>
        {
            new("groups", "[\"admin\",\"moderator\"]", Microsoft.IdentityModel.JsonWebTokens.JsonClaimValueTypes.JsonArray)
        });

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, token);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue();
    result.Principal!.IsInRole("admin").ShouldBeTrue();
    result.Principal!.IsInRole("moderator").ShouldBeTrue();
  }

  [Test]
  public async Task Should_MapRolesFromCustomNamedGroupClaim_OnJwt()
  {
    var options = JwtOptions(new OpenIdServerMock(), o => o.RoleClaimType = "groupsAlt");
    var token = OpenIdServerMock.CreateAccessToken();

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, token);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");

    // groupsAlt = [{ id = "editorId", name = "editor" }, { id = "viewerId", name = "viewer" }]
    result.Principal!.IsInRole("editor").ShouldBeTrue();
    result.Principal!.IsInRole("viewer").ShouldBeTrue();
    result.Principal!.IsInRole("editorId").ShouldBeTrue();
    result.Principal!.IsInRole("viewerId").ShouldBeTrue();

    // Specificity: the default "groups" claim has a different name, so its values must NOT be roles.
    result.Principal!.IsInRole("admin").ShouldBeFalse();
  }

  [Test]
  public async Task Should_InvokeTokenValidatedEvent_AndAllowResultOverride()
  {
    var invoked = false;
    var options = JwtOptions(new OpenIdServerMock(), o => o.Events.OnTokenValidated = ctx =>
    {
      invoked = true;
      ctx.Fail("rejected by event");
      return Task.CompletedTask;
    });
    var token = OpenIdServerMock.CreateAccessToken();

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, token);
    var result = await handler.AuthenticateAsync();

    invoked.ShouldBeTrue();
    result.Succeeded.ShouldBeFalse();
    result.Failure!.Message.ShouldBe("rejected by event");
  }

  [Test]
  public async Task Should_InvokeMessageReceivedEvent_AndUseSuppliedToken()
  {
    var token = OpenIdServerMock.CreateAccessToken();
    var options = JwtOptions(new OpenIdServerMock(), o => o.Events.OnMessageReceived = ctx =>
    {
      ctx.Token = token;
      return Task.CompletedTask;
    });

    // No Authorization header is supplied; the event provides the token.
    var (handler, _) = await HandlerTestHarness.CreateAsync(options);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue();
  }

  [Test]
  public async Task Should_ShortCircuit_When_MessageReceivedSetsResult()
  {
    var options = JwtOptions(new OpenIdServerMock(), o => o.Events.OnMessageReceived = ctx =>
    {
      ctx.NoResult();
      return Task.CompletedTask;
    });

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpenIdServerMock.CreateAccessToken());
    var result = await handler.AuthenticateAsync();

    result.None.ShouldBeTrue();
  }

  [Test]
  public async Task Should_InvokeAuthenticationFailedEvent_AndAllowSuppression()
  {
    var options = JwtOptions(new OpenIdServerMock(), o => o.Events.OnAuthenticationFailed = ctx =>
    {
      // Suppress the failure and succeed with a custom principal.
      var identity = new ClaimsIdentity("override");
      ctx.Principal = new ClaimsPrincipal(identity);
      ctx.Success();
      return Task.CompletedTask;
    });

    // Tamper so JWT validation fails and AuthenticationFailed runs.
    var token = OpenIdServerMock.CreateAccessToken();
    var tampered = token[..^3] + "ZZZ";

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, tampered);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue();
    result.Principal!.Identity!.AuthenticationType.ShouldBe("override");
  }
}
