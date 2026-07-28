namespace MonoCloud.Authentication.Api.Tests;

public class ClientAuthTests
{
  private const string AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

  private static (ClientAuthenticationContext Context, Dictionary<string, string> Payload, HttpRequestMessage Request) Build(Action<MonoCloudAuthenticationOptions>? configure = null)
  {
    var options = new MonoCloudAuthenticationOptions
    {
      ClientId = OpenIdServerMock.ClientId,
      ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(new OpenIdConnectConfiguration
      {
        Issuer = OpenIdServerMock.Issuer,
        TokenEndpoint = OpenIdServerMock.TokenEndpoint
      })
    };

    configure?.Invoke(options);

    var payload = new Dictionary<string, string>();
    var request = new HttpRequestMessage(HttpMethod.Post, OpenIdServerMock.IntrospectionEndpoint);
    var scheme = new AuthenticationScheme("MonoCloud", "MonoCloud", typeof(MonoCloudAuthenticationHandler));
    var context = new ClientAuthenticationContext(options, request, payload, new DefaultHttpContext(), scheme);

    return (context, payload, request);
  }

  private static async Task AssertValidAssertionAsync(string assertion, SecurityKey signingKey)
  {
    var result = await new JsonWebTokenHandler().ValidateTokenAsync(assertion, new TokenValidationParameters
    {
      ValidateIssuer = true,
      ValidIssuer = OpenIdServerMock.ClientId,
      ValidateAudience = true,
      ValidAudience = OpenIdServerMock.Issuer,
      ValidateLifetime = true,
      // Signature is still verified against IssuerSigningKey; we skip signing-key (X509 lifetime)
      // validation so the test does not depend on the fixture certificate's validity period.
      ValidateIssuerSigningKey = false,
      IssuerSigningKey = signingKey,
      ClockSkew = TimeSpan.Zero
    });

    result.IsValid.ShouldBeTrue(result.Exception?.ToString() ?? "assertion invalid");
    result.ClaimsIdentity.FindFirst("sub")!.Value.ShouldBe(OpenIdServerMock.ClientId);
    result.ClaimsIdentity.FindFirst("jti").ShouldNotBeNull();

    var rawPayload = JsonDocument.Parse(Base64UrlEncoder.Decode(assertion.Split('.')[1])).RootElement;

    var aud = rawPayload.GetProperty("aud");
    aud.ValueKind.ShouldBe(JsonValueKind.String, "aud must be a single string, not an array");
    aud.GetString().ShouldBe(OpenIdServerMock.Issuer);
  }

  [Test]
  public async Task ClientSecretAuth_Post_AddsClientIdAndSecretToPayload()
  {
    var (context, payload, request) = Build();

    await new ClientSecretAuth(OpenIdServerMock.SymmetricSecret).AuthenticateAsync(context, default);

    payload["client_id"].ShouldBe(OpenIdServerMock.ClientId);
    payload["client_secret"].ShouldBe(OpenIdServerMock.SymmetricSecret);
    request.Headers.Authorization.ShouldBeNull();
  }

  [Test]
  public async Task ClientSecretAuth_Basic_AddsAuthorizationHeader()
  {
    var (context, payload, request) = Build();

    await new ClientSecretAuth(OpenIdServerMock.SymmetricSecret, clientSecretBasic: true).AuthenticateAsync(context, default);

    request.Headers.Authorization!.Scheme.ShouldBe("Basic");
    var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(request.Headers.Authorization.Parameter!));
    decoded.ShouldBe($"{OpenIdServerMock.ClientId}:{OpenIdServerMock.SymmetricSecret}");
    payload.ShouldNotContainKey("client_secret");
  }

  [Test]
  public async Task ClientSecretAuth_Throws_When_ClientIdMissing()
  {
    var (context, _, _) = Build(o => o.ClientId = null);

    await Should.ThrowAsync<ArgumentNullException>(() => new ClientSecretAuth(OpenIdServerMock.SymmetricSecret).AuthenticateAsync(context, default));
  }

  [Test]
  public async Task TlsAuth_AddsClientIdToPayload()
  {
    var (context, payload, _) = Build();

    await new TlsAuth().AuthenticateAsync(context, default);

    payload["client_id"].ShouldBe(OpenIdServerMock.ClientId);
    payload.ShouldNotContainKey("client_secret");
  }

  [Test]
  public async Task TlsAuth_Throws_When_ClientIdMissing()
  {
    var (context, _, _) = Build(o => o.ClientId = null);

    await Should.ThrowAsync<ArgumentNullException>(() => new TlsAuth().AuthenticateAsync(context, default));
  }

  [Test]
  public async Task JwtAssertionAuth_WithClientSecret_ProducesValidHmacAssertion()
  {
    var (context, payload, _) = Build();

    await new JwtAssertionAuth(OpenIdServerMock.SymmetricSecret).AuthenticateAsync(context, default);

    payload["client_assertion_type"].ShouldBe(AssertionType);
    new JsonWebToken(payload["client_assertion"]).Alg.ShouldBe(SecurityAlgorithms.HmacSha256);
    await AssertValidAssertionAsync(payload["client_assertion"], new SymmetricSecurityKey(Encoding.UTF8.GetBytes(OpenIdServerMock.SymmetricSecret)));
  }

  [Test]
  public async Task JwtAssertionAuth_WithJwk_ProducesValidRsaAssertion()
  {
    var (context, payload, _) = Build();

    await new JwtAssertionAuth(OpenIdServerMock.PrivateJwkKey).AuthenticateAsync(context, default);

    payload["client_assertion_type"].ShouldBe(AssertionType);
    new JsonWebToken(payload["client_assertion"]).Alg.ShouldBe(SecurityAlgorithms.RsaSha256);
    await AssertValidAssertionAsync(payload["client_assertion"], OpenIdServerMock.PublicJwkKey);
  }

  [Test]
  public async Task JwtAssertionAuth_WithCertificate_ProducesValidRsaAssertion()
  {
    var (context, payload, _) = Build();

    await new JwtAssertionAuth(OpenIdServerMock.PrivateKeyCert).AuthenticateAsync(context, default);

    payload["client_assertion_type"].ShouldBe(AssertionType);
    await AssertValidAssertionAsync(payload["client_assertion"], new X509SecurityKey(OpenIdServerMock.PrivateKeyCert));
  }

  [Test]
  public async Task JwtAssertionAuth_RespectsSigningAlgorithmOverride()
  {
    var (context, payload, _) = Build(o => o.JwtAssertionSigningAlgorithm = SecurityAlgorithms.RsaSha512);

    await new JwtAssertionAuth(OpenIdServerMock.PrivateKeyCert).AuthenticateAsync(context, default);

    new JsonWebToken(payload["client_assertion"]).Alg.ShouldBe(SecurityAlgorithms.RsaSha512);
  }

  [Test]
  public async Task JwtAssertionAuth_UsesCustomAssertionFromEvent()
  {
    var (context, payload, _) = Build(o => o.Events.OnCreatingJwtAssertion = ctx =>
    {
      ctx.JwtAssertion = new JwtAssertion
      {
        Assertion = "custom-assertion-value",
        AssertionType = "custom-assertion-type"
      };
      return Task.CompletedTask;
    });

    await new JwtAssertionAuth(OpenIdServerMock.SymmetricSecret).AuthenticateAsync(context, default);

    payload["client_assertion"].ShouldBe("custom-assertion-value");
    payload["client_assertion_type"].ShouldBe("custom-assertion-type");
  }

  [Test]
  public async Task JwtAssertionAuth_Throws_When_ClientIdMissing()
  {
    var (context, _, _) = Build(o => o.ClientId = null);

    await Should.ThrowAsync<ArgumentNullException>(() => new JwtAssertionAuth(OpenIdServerMock.SymmetricSecret).AuthenticateAsync(context, default));
  }

  [Test]
  public async Task SpiffeJwtAuth_ForwardsJwtSvidAsClientAssertion()
  {
    var (context, payload, request) = Build();

    await new SpiffeJwtAuth("spiffe-jwt-svid").AuthenticateAsync(context, default);

    payload["client_id"].ShouldBe(OpenIdServerMock.ClientId);
    payload["client_assertion_type"].ShouldBe("urn:ietf:params:oauth:client-assertion-type:jwt-spiffe");
    payload["client_assertion"].ShouldBe("spiffe-jwt-svid");
    request.Headers.Authorization.ShouldBeNull();
  }

  [Test]
  public async Task SpiffeJwtAuth_InvokesProvider_ForEachRequest()
  {
    var svids = new Queue<string>(new[] { "svid-1", "svid-2" });
    var auth = new SpiffeJwtAuth((_, _) => Task.FromResult(svids.Dequeue()));

    var (context1, payload1, _) = Build();
    await auth.AuthenticateAsync(context1, default);
    payload1["client_assertion"].ShouldBe("svid-1");

    // A rotated SVID must be picked up on the next request without recreating the auth instance.
    var (context2, payload2, _) = Build();
    await auth.AuthenticateAsync(context2, default);
    payload2["client_assertion"].ShouldBe("svid-2");
  }

  [Test]
  public async Task SpiffeJwtAuth_ProviderCanResolveServices_FromHttpContext()
  {
    var (context, payload, _) = Build();

    // A per-request SVID source registered in DI (e.g. a SPIFFE Workload API client) must be
    // reachable from the provider via HttpContext.RequestServices.
    var services = new ServiceCollection();
    services.AddSingleton(new SvidSource("svid-from-di"));
    context.HttpContext.RequestServices = services.BuildServiceProvider();

    var auth = new SpiffeJwtAuth((httpContext, _) => Task.FromResult(httpContext.RequestServices.GetRequiredService<SvidSource>().Svid));

    await auth.AuthenticateAsync(context, default);

    payload["client_assertion"].ShouldBe("svid-from-di");
  }

  [Test]
  public async Task SpiffeJwtAuth_Throws_When_ClientIdMissing()
  {
    var (context, _, _) = Build(o => o.ClientId = null);

    await Should.ThrowAsync<ArgumentNullException>(() => new SpiffeJwtAuth("spiffe-jwt-svid").AuthenticateAsync(context, default));
  }

  [Test]
  public async Task SpiffeJwtAuth_Throws_When_ProviderReturnsNoSvid()
  {
    var (context, _, _) = Build();

    await Should.ThrowAsync<InvalidOperationException>(() => new SpiffeJwtAuth((_, _) => Task.FromResult<string>(null!)).AuthenticateAsync(context, default));
  }

  [Test]
  public async Task SpiffeX509Auth_IsAnMtlsMethod_AndAddsOnlyClientIdToPayload()
  {
    var (context, payload, request) = Build();

    var auth = new SpiffeX509Auth();

    // Must remain a TlsAuth so the handler resolves the mTLS introspection endpoint alias and
    // PostConfigure attaches the X.509-SVID to the HttpClient.
    auth.ShouldBeAssignableTo<TlsAuth>();

    await auth.AuthenticateAsync(context, default);

    payload["client_id"].ShouldBe(OpenIdServerMock.ClientId);
    payload.Count.ShouldBe(1);
    request.Headers.Authorization.ShouldBeNull();
  }

  [Test]
  public async Task SpiffeX509Auth_Throws_When_ClientIdMissing()
  {
    var (context, _, _) = Build(o => o.ClientId = null);

    await Should.ThrowAsync<ArgumentNullException>(() => new SpiffeX509Auth().AuthenticateAsync(context, default));
  }

  // A stand-in for a service (e.g. a SPIFFE Workload API client) resolved from HttpContext.RequestServices.
  private sealed record SvidSource(string Svid);
}
