namespace MonoCloud.Authentication.Api.Tests;

public class MonoCloudAuthenticationHandlerIntrospectionTests
{
  private const string OpaqueToken = "opaque-access-token";

  private static MonoCloudAuthenticationOptions OpaqueOptions(
      OpenIdServerMock server,
      IMonoCloudClientAuth? clientAuth = null,
      Action<MonoCloudAuthenticationOptions>? configure = null)
  {
    var options = new MonoCloudAuthenticationOptions
    {
      TenantDomain = OpenIdServerMock.Issuer,
      ClientId = OpenIdServerMock.ClientId,
      ClientAuth = clientAuth ?? new ClientSecretAuth(OpenIdServerMock.SymmetricSecret),
      HttpClient = server.Build()
    };

    configure?.Invoke(options);

    return options;
  }

  [Test]
  public async Task Should_Authenticate_When_TokenIsActive()
  {
    var server = new OpenIdServerMock();
    server.SetupDiscovery();
    server.SetupJwks();
    server.SetupIntrospection(authType: "client_secret_post");

    var options = OpaqueOptions(server);

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
    result.Principal!.FindFirst("sub")!.Value.ShouldBe("1234567890");
    result.Principal!.FindAll("scope").Select(c => c.Value).ShouldBe(new[] { "openid", "resource" }, ignoreOrder: true);
    result.Principal!.HasClaim("active", "true").ShouldBeTrue();
  }

  [Test]
  public async Task Should_NormalizeObjectArrayGroupClaims_When_RoleClaimTypeIsSet()
  {
    var server = new OpenIdServerMock();
    server.SetupDiscovery();
    server.SetupJwks();
    server.SetupIntrospection(authType: "client_secret_post");

    // The introspection response sends groups as an OBJECT array:
    //   [{ "id": "adminId", "name": "admin" }, { "id": "moderatorId", "name": "moderator" }]
    var options = OpaqueOptions(server, configure: o => o.RoleClaimType = "groups");

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");

    // Each { id, name } object must be expanded into BOTH its id and its name under the role
    // claim type, so introspection tokens get the same role checks as JWTs.
    result.Principal!.IsInRole("admin").ShouldBeTrue();
    result.Principal!.IsInRole("moderator").ShouldBeTrue();
    result.Principal!.IsInRole("adminId").ShouldBeTrue();
    result.Principal!.IsInRole("moderatorId").ShouldBeTrue();

    // The raw group object JSON must NOT survive as a role value — proves normalization actually
    // ran (rather than the assertion matching a pre-existing claim).
    result.Principal!.IsInRole("""{"id":"adminId","name":"admin"}""").ShouldBeFalse();

    result.Principal!.FindAll("groups").Select(c => c.Value)
        .ShouldBe(new[] { "adminId", "admin", "moderatorId", "moderator" }, ignoreOrder: true);
  }

  [Test]
  public async Task Should_NotNormalizeGroupClaims_When_RoleClaimTypeIsNotSet()
  {
    var server = new OpenIdServerMock();
    server.SetupDiscovery();
    server.SetupJwks();
    server.SetupIntrospection(authType: "client_secret_post");

    // No RoleClaimType configured, so group normalization must not run.
    var options = OpaqueOptions(server);

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");

    // The two group objects remain unexpanded (still 2 object-valued claims, not 4 id/name claims).
    var groups = result.Principal!.FindAll("groups").Select(c => c.Value).ToList();
    groups.Count.ShouldBe(2);
    groups.ShouldAllBe(v => v.Contains("\"id\"") && v.Contains("\"name\""));
    groups.ShouldNotContain("admin");
  }

  [Test]
  public async Task Should_MapRolesFromCustomNamedGroupClaim_OnIntrospection()
  {
    var server = new OpenIdServerMock();
    server.SetupDiscovery();
    server.SetupJwks();
    server.SetupIntrospection(authType: "client_secret_post");

    // A tenant can surface groups under a custom claim name; the shape is still { id, name } objects.
    var options = OpaqueOptions(server, configure: o => o.RoleClaimType = "groupsAlt");

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");

    // groupsAlt = [{ id = "editorId", name = "editor" }, { id = "viewerId", name = "viewer" }]
    result.Principal!.IsInRole("editor").ShouldBeTrue();
    result.Principal!.IsInRole("viewer").ShouldBeTrue();
    result.Principal!.IsInRole("editorId").ShouldBeTrue();
    result.Principal!.IsInRole("viewerId").ShouldBeTrue();

    // Specificity: the default "groups" claim has a different name, so its values must NOT be roles.
    result.Principal!.IsInRole("admin").ShouldBeFalse();
    result.Principal!.IsInRole("moderator").ShouldBeFalse();
  }

  [Test]
  public async Task Should_Fail_When_TokenIsInactive()
  {
    var server = new OpenIdServerMock();
    server.SetupDiscovery();
    server.SetupJwks();
    server.SetupIntrospection(failure: true, authType: "client_secret_post");

    var options = OpaqueOptions(server);

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeFalse();
    result.Failure!.Message.ShouldBe("Token inactive");
  }

  [Test]
  public async Task Should_Fail_When_IntrospectionReturnsError()
  {
    var server = new OpenIdServerMock();
    server.SetupDiscovery();
    server.SetupJwks();
    server.SetupIntrospection(status: HttpStatusCode.InternalServerError, authType: "client_secret_post");

    var options = OpaqueOptions(server);

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeFalse();
    result.Failure!.Message.ShouldBe("Introspection failed");
  }

  [Test]
  public async Task Should_Throw_When_ClientIdIsMissing()
  {
    var server = new OpenIdServerMock();
    var options = OpaqueOptions(server, configure: o => o.ClientId = null);

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);

    await Should.ThrowAsync<ArgumentNullException>(() => handler.AuthenticateAsync());
  }

  [Test]
  public async Task Should_Throw_When_TenantDomainIsMissing()
  {
    var server = new OpenIdServerMock();
    var options = OpaqueOptions(server, configure: o => o.TenantDomain = null);

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);

    await Should.ThrowAsync<ArgumentNullException>(() => handler.AuthenticateAsync());
  }

  [Test]
  public async Task Should_StoreAccessToken_When_SaveTokenIsEnabled()
  {
    var server = new OpenIdServerMock();
    server.SetupDiscovery();
    server.SetupJwks();
    server.SetupIntrospection(authType: "client_secret_post");

    var options = OpaqueOptions(server, configure: o => o.SaveToken = true);

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue();
    result.Properties!.GetTokenValue("access_token").ShouldBe(OpaqueToken);
  }

  [Test]
  public async Task Should_InvokeIntrospectionEvent()
  {
    var invoked = false;
    var server = new OpenIdServerMock();
    server.SetupDiscovery();
    server.SetupJwks();
    server.SetupIntrospection(authType: "client_secret_post");

    var options = OpaqueOptions(server, configure: o => o.Events.OnIntrospection = _ =>
    {
      invoked = true;
      return Task.CompletedTask;
    });

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);
    await handler.AuthenticateAsync();

    invoked.ShouldBeTrue();
  }

  [Test]
  public async Task Should_IntrospectJwt_When_IntrospectJwtTokensIsEnabled()
  {
    var server = new OpenIdServerMock();
    server.SetupDiscovery();
    server.SetupJwks();
    server.SetupIntrospection(authType: "client_secret_post");

    var options = OpaqueOptions(server, configure: o => o.IntrospectJwtTokens = true);
    // A real JWT — but it must be routed through introspection, not signature validation.
    var jwt = OpenIdServerMock.CreateAccessToken();

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, jwt);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
    result.Principal!.FindAll("scope").Select(c => c.Value).ShouldBe(new[] { "openid", "resource" }, ignoreOrder: true);
  }

  [Test]
  public async Task Should_AuthenticateWithClientSecretBasic()
  {
    var server = new OpenIdServerMock();
    server.SetupDiscovery();
    server.SetupJwks();
    server.SetupIntrospection(authType: "client_secret_basic");

    var options = OpaqueOptions(server, new ClientSecretAuth(OpenIdServerMock.SymmetricSecret, clientSecretBasic: true));

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
  }

  [Test]
  public async Task Should_AuthenticateWithClientSecretJwt()
  {
    var server = new OpenIdServerMock();
    server.SetupDiscovery();
    server.SetupJwks();
    server.SetupIntrospection(authType: "client_secret_jwt");

    var options = OpaqueOptions(server, new JwtAssertionAuth(OpenIdServerMock.SymmetricSecret));

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
  }

  [Test]
  public async Task Should_AuthenticateWithPrivateKeyJwt()
  {
    var server = new OpenIdServerMock();
    server.SetupDiscovery();
    server.SetupJwks();
    server.SetupIntrospection(authType: "private_key_jwt");

    // Signed with the private JWK whose public counterpart the server uses to validate the assertion.
    var options = OpaqueOptions(server, new JwtAssertionAuth(OpenIdServerMock.PrivateJwkKey));

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
  }

  [Test]
  public async Task Should_ReturnClaimsFromCache_OnSecondRequest()
  {
    var cache = new IntrospectionCacheMock();
    const string token = "opaque-cached-active";

    // First request: introspects and caches the claims.
    var server1 = new OpenIdServerMock();
    server1.SetupDiscovery();
    server1.SetupJwks();
    server1.SetupIntrospection(authType: "client_secret_post");
    var options1 = OpaqueOptions(server1, configure: o => o.EnableCaching = true);
    var (handler1, _) = await HandlerTestHarness.CreateAsync(options1, token, cache);
    (await handler1.AuthenticateAsync()).Succeeded.ShouldBeTrue();
    cache.SetCount.ShouldBe(1);

    // Second request: no introspection endpoint configured — success can only come from the cache.
    var server2 = new OpenIdServerMock();
    server2.SetupDiscovery();
    server2.SetupJwks();
    var options2 = OpaqueOptions(server2, configure: o => o.EnableCaching = true);
    var (handler2, _) = await HandlerTestHarness.CreateAsync(options2, token, cache);
    var result = await handler2.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
    cache.SetCount.ShouldBe(1); // not written again
  }

  [Test]
  public async Task Should_Fail_When_CachedTokenIsInactive()
  {
    var cache = new IntrospectionCacheMock();
    const string token = "opaque-cached-inactive";

    var server = new OpenIdServerMock();
    var options = OpaqueOptions(server, configure: o => o.EnableCaching = true);

    // CreateAsync runs PostConfigure, which assigns the scheme name used in the cache key.
    var (handler, _) = await HandlerTestHarness.CreateAsync(options, token, cache);

    // Seed the cache with an inactive-token claims document.
    var key = options.CacheKeyGenerator(options, token);
    await cache.SetAsync(key, "[{\"Type\":\"active\",\"Value\":\"false\"},{\"Type\":\"exp\",\"Value\":\"9999999999\"}]", TimeSpan.FromMinutes(5));

    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeFalse();
    result.Failure!.Message.ShouldBe("Token inactive");
  }

  [Test]
  public async Task Should_CacheInactiveToken_AndFailFromCache_OnSecondRequest()
  {
    var cache = new IntrospectionCacheMock();
    const string token = "opaque-cached-inactive-roundtrip";

    // First request: introspection reports the token inactive; the inactive claims are cached.
    var server1 = new OpenIdServerMock();
    server1.SetupDiscovery();
    server1.SetupJwks();
    server1.SetupIntrospection(failure: true, authType: "client_secret_post");
    var options1 = OpaqueOptions(server1, configure: o => o.EnableCaching = true);
    var (handler1, _) = await HandlerTestHarness.CreateAsync(options1, token, cache);
    (await handler1.AuthenticateAsync()).Succeeded.ShouldBeFalse();
    cache.SetCount.ShouldBe(1);

    // Second request: no introspection endpoint configured — the inactive verdict can only come from the cache.
    var server2 = new OpenIdServerMock();
    server2.SetupDiscovery();
    server2.SetupJwks();
    var options2 = OpaqueOptions(server2, configure: o => o.EnableCaching = true);
    var (handler2, _) = await HandlerTestHarness.CreateAsync(options2, token, cache);
    var result = await handler2.AuthenticateAsync();

    result.Succeeded.ShouldBeFalse();
    result.Failure!.Message.ShouldBe("Token inactive");
    cache.SetCount.ShouldBe(1); // not written again
  }
}
