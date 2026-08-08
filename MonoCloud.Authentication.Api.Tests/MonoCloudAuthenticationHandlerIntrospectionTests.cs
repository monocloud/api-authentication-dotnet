namespace MonoCloud.Authentication.Api.Tests;

public class MonoCloudAuthenticationHandlerIntrospectionTests
{
  private const string OpaqueToken = "opaque-access-token";

  private static MonoCloudAuthenticationOptions OpaqueOptions(OpenIdServerMock server, IMonoCloudClientAuth? clientAuth = null, Action<MonoCloudAuthenticationOptions>? configure = null)
  {
    var options = new MonoCloudAuthenticationOptions
    {
      Authority = OpenIdServerMock.Issuer,
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
    result.Principal!.FindAll("scope").Select(c => c.Value).ShouldBe(["openid", "resource"], ignoreOrder: true);
    result.Principal!.HasClaim("active", "true").ShouldBeTrue();

    server.VerifyDiscoveryCalled();
    server.VerifyJwksCalled();
    server.VerifyIntrospectionCalled();
  }

  [Test]
  public async Task Should_NormalizeObjectArrayGroupClaims_When_RoleClaimTypeIsSet()
  {
    var server = new OpenIdServerMock();
    server.SetupDiscovery();
    server.SetupJwks();
    server.SetupIntrospection(authType: "client_secret_post");

    var options = OpaqueOptions(server, configure: o => o.RoleClaimType = "groups");

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");

    result.Principal!.IsInRole("admin").ShouldBeTrue();
    result.Principal!.IsInRole("moderator").ShouldBeTrue();
    result.Principal!.IsInRole("adminId").ShouldBeTrue();
    result.Principal!.IsInRole("moderatorId").ShouldBeTrue();

    result.Principal!.IsInRole("""{"id":"adminId","name":"admin"}""").ShouldBeFalse();

    result.Principal!.FindAll("groups").Select(c => c.Value).ShouldBe(["adminId", "admin", "moderatorId", "moderator"], ignoreOrder: true);
  }

  [Test]
  public async Task Should_NotNormalizeGroupClaims_When_RoleClaimTypeIsNotSet()
  {
    var server = new OpenIdServerMock();
    server.SetupDiscovery();
    server.SetupJwks();
    server.SetupIntrospection(authType: "client_secret_post");

    var options = OpaqueOptions(server);

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");

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

    var options = OpaqueOptions(server, configure: o => o.RoleClaimType = "groupsAlt");

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");

    result.Principal!.IsInRole("editor").ShouldBeTrue();
    result.Principal!.IsInRole("viewer").ShouldBeTrue();
    result.Principal!.IsInRole("editorId").ShouldBeTrue();
    result.Principal!.IsInRole("viewerId").ShouldBeTrue();

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
  public async Task Should_Throw_When_AuthorityIsMissing()
  {
    var server = new OpenIdServerMock();
    var options = OpaqueOptions(server, configure: o => o.Authority = null);

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
    var jwt = OpenIdServerMock.CreateAccessToken();

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, jwt);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
    result.Principal!.FindAll("scope").Select(c => c.Value).ShouldBe(["openid", "resource"], ignoreOrder: true);
    server.VerifyIntrospectionCalled();
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
  public async Task Should_AuthenticateWithSpiffeJwt()
  {
    var server = new OpenIdServerMock();
    server.SetupDiscovery();
    server.SetupJwks();
    server.SetupIntrospection(authType: "spiffe_jwt");

    var options = OpaqueOptions(server, new SpiffeJwtAuth(OpenIdServerMock.SpiffeJwtSvid));

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
    server.VerifyIntrospectionCalled();
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
    server1.VerifyIntrospectionCalled();
    server2.VerifyIntrospectionCalled(Times.Never()); // served entirely from the cache
  }

  [Test]
  public async Task Should_ReIntrospect_AfterCachedClaimsAreDeleted()
  {
    var cache = new IntrospectionCacheMock();
    const string token = "opaque-evicted-active";

    // First request: introspects and caches the claims.
    var server1 = new OpenIdServerMock();
    server1.SetupDiscovery();
    server1.SetupJwks();
    server1.SetupIntrospection(authType: "client_secret_post");
    var options1 = OpaqueOptions(server1, configure: o => o.EnableCaching = true);
    var (handler1, _) = await HandlerTestHarness.CreateAsync(options1, token, cache);
    (await handler1.AuthenticateAsync()).Succeeded.ShouldBeTrue();
    cache.SetCount.ShouldBe(1);

    // Evict the entry the way a consumer would (e.g. on token revocation): generate the key and delete.
    await cache.DeleteAsync(options1.CacheKeyGenerator(options1, token));
    cache.DeleteCount.ShouldBe(1);

    // Second request: the cache no longer answers, so the handler must introspect again.
    var server2 = new OpenIdServerMock();
    server2.SetupDiscovery();
    server2.SetupJwks();
    server2.SetupIntrospection(authType: "client_secret_post");
    var options2 = OpaqueOptions(server2, configure: o => o.EnableCaching = true);
    var (handler2, _) = await HandlerTestHarness.CreateAsync(options2, token, cache);
    var result = await handler2.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
    server2.VerifyIntrospectionCalled();
    cache.SetCount.ShouldBe(2);
  }

  [Test]
  public async Task Should_Authenticate_AfterCachedInactiveTokenIsDeleted()
  {
    var cache = new IntrospectionCacheMock();
    const string token = "opaque-evicted-inactive";

    // Seed the cache with an inactive verdict, as a prior introspection would have left it.
    var server1 = new OpenIdServerMock();
    var options1 = OpaqueOptions(server1, configure: o => o.EnableCaching = true);
    var (handler1, _) = await HandlerTestHarness.CreateAsync(options1, token, cache);
    var key = options1.CacheKeyGenerator(options1, token);
    await cache.SetAsync(key, "[{\"Type\":\"active\",\"Value\":\"false\"},{\"Type\":\"exp\",\"Value\":\"9999999999\"}]", TimeSpan.FromMinutes(5));

    (await handler1.AuthenticateAsync()).Failure!.Message.ShouldBe("Token inactive");
    server1.VerifyIntrospectionCalled(Times.Never());

    // Evicting the stale inactive verdict lets the next request reach the introspection endpoint again.
    await cache.DeleteAsync(key);

    var server2 = new OpenIdServerMock();
    server2.SetupDiscovery();
    server2.SetupJwks();
    server2.SetupIntrospection(authType: "client_secret_post");
    var options2 = OpaqueOptions(server2, configure: o => o.EnableCaching = true);
    var (handler2, _) = await HandlerTestHarness.CreateAsync(options2, token, cache);
    var result = await handler2.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
    server2.VerifyIntrospectionCalled();
  }

  [Test]
  public async Task DeleteAsync_RemovesOnlyTheRequestedEntry()
  {
    var cache = new IntrospectionCacheMock();

    await cache.SetAsync("key-one", "value-one", TimeSpan.FromMinutes(5));
    await cache.SetAsync("key-two", "value-two", TimeSpan.FromMinutes(5));

    await cache.DeleteAsync("key-one");

    (await cache.GetAsync("key-one")).ShouldBeNull();
    (await cache.GetAsync("key-two")).ShouldBe("value-two");

    await Should.NotThrowAsync(() => cache.DeleteAsync("key-one"));
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
    server.VerifyIntrospectionCalled(Times.Never()); // the cached inactive verdict short-circuits introspection
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
    cache.SetCount.ShouldBe(1);
    server1.VerifyIntrospectionCalled();
    server2.VerifyIntrospectionCalled(Times.Never());
  }

  [Test]
  public async Task Should_CacheInactiveVerdict_When_ResponseLacksActiveProperty()
  {
    var cache = new IntrospectionCacheMock();
    const string token = "opaque-cached-no-active-property";

    // First request: the introspection response has NO "active" property at all, which RFC 7662
    // parsing treats as inactive. The handler must synthesize an active=false claim before caching.
    var server1 = new OpenIdServerMock();
    server1.SetupDiscovery();
    server1.SetupJwks();
    server1.SetupIntrospection(authType: "client_secret_post", body: new { sub = "1234567890" });
    var options1 = OpaqueOptions(server1, configure: o => o.EnableCaching = true);
    var (handler1, _) = await HandlerTestHarness.CreateAsync(options1, token, cache);
    var first = await handler1.AuthenticateAsync();
    first.Succeeded.ShouldBeFalse();
    first.Failure!.Message.ShouldBe("Token inactive");
    cache.SetCount.ShouldBe(1);

    // Second request: no introspection endpoint configured — the verdict can only come from the
    // cache. Without the synthesized claim the cached copy would be treated as ACTIVE and accepted.
    var server2 = new OpenIdServerMock();
    server2.SetupDiscovery();
    server2.SetupJwks();
    var options2 = OpaqueOptions(server2, configure: o => o.EnableCaching = true);
    var (handler2, _) = await HandlerTestHarness.CreateAsync(options2, token, cache);
    var result = await handler2.AuthenticateAsync();

    result.Succeeded.ShouldBeFalse();
    result.Failure!.Message.ShouldBe("Token inactive");
    cache.SetCount.ShouldBe(1); // not written again
    server1.VerifyIntrospectionCalled();
    server2.VerifyIntrospectionCalled(Times.Never()); // the inactive verdict came from the cache
  }

  [Test]
  public async Task Should_FallBackToIntrospection_When_CacheReadThrows()
  {
    var cache = new IntrospectionCacheMock { ThrowOnGet = true };

    var server = new OpenIdServerMock();
    server.SetupDiscovery();
    server.SetupJwks();
    server.SetupIntrospection(authType: "client_secret_post");

    var options = OpaqueOptions(server, configure: o => o.EnableCaching = true);

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, "opaque-cache-error-token", cache);
    var result = await handler.AuthenticateAsync();

    // An unavailable cache must degrade to a live introspection, not fail authentication.
    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
    server.VerifyIntrospectionCalled();
    cache.SetCount.ShouldBe(1);
  }

  [Test]
  public async Task Should_CollapseConcurrentIntrospections_ForTheSameToken()
  {
    const string token = "opaque-concurrent-token";

    var firstCallStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var releaseIntrospection = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

    var server = new OpenIdServerMock();
    server.SetupDiscovery();
    server.SetupJwks();
    server.SetupIntrospection(authType: "client_secret_post", beforeRespond: async () =>
    {
      firstCallStarted.TrySetResult();
      await releaseIntrospection.Task;
    });

    var options = OpaqueOptions(server);
    var (handler1, _) = await HandlerTestHarness.CreateAsync(options, token);
    var (handler2, _) = await HandlerTestHarness.CreateAsync(options, token);

    var first = handler1.AuthenticateAsync();
    await firstCallStarted.Task.WaitAsync(TimeSpan.FromSeconds(10));
    var second = handler2.AuthenticateAsync();
    releaseIntrospection.SetResult();

    var results = await Task.WhenAll(first, second);

    results[0].Succeeded.ShouldBeTrue(results[0].Failure?.ToString() ?? "no failure");
    results[1].Succeeded.ShouldBeTrue(results[1].Failure?.ToString() ?? "no failure");
    server.VerifyIntrospectionCalled();
  }
}
