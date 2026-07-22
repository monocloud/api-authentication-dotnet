namespace MonoCloud.Authentication.Api.Tests;

public class ClientAuthTests
{
  private const string AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

  private static (ClientAuthenticationContext Context, Dictionary<string, string> Payload, HttpRequestMessage Request) Build(
      Action<MonoCloudAuthenticationOptions>? configure = null)
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
      ValidAudience = OpenIdServerMock.TokenEndpoint,
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
}
