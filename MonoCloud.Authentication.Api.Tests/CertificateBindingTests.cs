namespace MonoCloud.Authentication.Api.Tests;

public class CertificateBindingTests
{
  private static MonoCloudAuthenticationOptions BindingOptions(OpenIdServerMock server, Action<MonoCloudAuthenticationOptions>? configure = null)
  {
    server.SetupDiscovery();
    server.SetupJwks();

    var options = new MonoCloudAuthenticationOptions
    {
      TenantDomain = OpenIdServerMock.Issuer,
      Audience = OpenIdServerMock.Issuer,
      MapInboundClaims = false,
      ValidateCertificateBinding = _ => true,
      HttpClient = server.Build()
    };

    configure?.Invoke(options);

    return options;
  }

  private static MonoCloudAuthenticationOptions OpaqueBindingOptions(OpenIdServerMock server, Action<MonoCloudAuthenticationOptions>? configure = null)
  {
    server.SetupDiscovery();
    server.SetupJwks();

    var options = new MonoCloudAuthenticationOptions
    {
      TenantDomain = OpenIdServerMock.Issuer,
      ClientId = OpenIdServerMock.ClientId,
      ClientAuth = new ClientSecretAuth(OpenIdServerMock.SymmetricSecret),
      ValidateCertificateBinding = _ => true,
      HttpClient = server.Build()
    };

    configure?.Invoke(options);

    return options;
  }


  [Test]
  public async Task Should_Succeed_When_CertificateMatchesBinding()
  {
    var bindingValidated = false;

    var options = BindingOptions(
      new OpenIdServerMock(),
      o => o.Events.OnCertificateBindingValidated = _ =>
      {
        bindingValidated = true;
        return Task.CompletedTask;
      });

    var token = OpenIdServerMock.CreateAccessToken();

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, token, clientCertificate: OpenIdServerMock.MtlsClientCert);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
    bindingValidated.ShouldBeTrue();
  }

  [Test]
  public async Task Should_Fail_When_ClientCertificateIsMissing()
  {
    var options = BindingOptions(new OpenIdServerMock());
    var token = OpenIdServerMock.CreateAccessToken();

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, token);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeFalse();
    result.Failure!.Message.ShouldBe("Client certificate is not present");
  }

  [Test]
  public async Task Should_Fail_When_TokenHasNoCnfClaim()
  {
    var options = BindingOptions(new OpenIdServerMock());
    var token = OpenIdServerMock.CreateAccessToken(excludeClaims: ["cnf"]);

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, token, clientCertificate: OpenIdServerMock.MtlsClientCert);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeFalse();
    result.Failure!.Message.ShouldBe("Access token does not contain a 'cnf' (confirmation) claim for certificate binding");
  }

  [Test]
  public async Task Should_Fail_When_CnfClaimIsMalformed()
  {
    var options = BindingOptions(new OpenIdServerMock());
    var token = OpenIdServerMock.CreateAccessToken(new List<Claim> { new("cnf", "not-json") });

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, token, clientCertificate: OpenIdServerMock.MtlsClientCert);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeFalse();
    result.Failure!.Message.ShouldBe("Malformed 'cnf' claim for certificate binding");
  }

  [Test]
  public async Task Should_Fail_When_CnfHasNoThumbprintMember()
  {
    var options = BindingOptions(new OpenIdServerMock());
    var token = OpenIdServerMock.CreateAccessToken(new List<Claim> { new("cnf", "{\"foo\":\"bar\"}", JsonClaimValueTypes.Json) });

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, token, clientCertificate: OpenIdServerMock.MtlsClientCert);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeFalse();
    result.Failure!.Message.ShouldBe("The 'cnf' claim does not contain an 'x5t#S256' member specifying the certificate hash for binding");
  }

  [Test]
  public async Task Should_Fail_When_CertificateHashDoesNotMatch()
  {
    var options = BindingOptions(new OpenIdServerMock());

    var token = OpenIdServerMock.CreateAccessToken(new List<Claim>
    {
      new("cnf", "{\"x5t#S256\":\"a-different-thumbprint\"}", JsonClaimValueTypes.Json)
    });

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, token, clientCertificate: OpenIdServerMock.MtlsClientCert);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeFalse();

    result.Failure!.Message.ShouldBe(
      "The certificate hash in the access token does not match the presented client certificate (certificate binding validation failed)");
  }

  [Test]
  public async Task Should_NotValidateBinding_When_PredicateReturnsFalse()
  {
    // Default predicate is false; even with no client certificate present, auth should succeed.
    var server = new OpenIdServerMock();
    server.SetupDiscovery();
    server.SetupJwks();

    var options = new MonoCloudAuthenticationOptions
    {
      TenantDomain = OpenIdServerMock.Issuer,
      Audience = OpenIdServerMock.Issuer,
      MapInboundClaims = false,
      HttpClient = server.Build()
    };

    var token = OpenIdServerMock.CreateAccessToken();

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, token);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
  }

  [Test]
  public async Task Should_UseCustomCertificateRetriever_When_Configured()
  {
    var options = BindingOptions(new OpenIdServerMock(),
      o => o.CertificateRetriever = _ => Task.FromResult<X509Certificate2?>(OpenIdServerMock.MtlsClientCert));

    var token = OpenIdServerMock.CreateAccessToken();

    // No certificate is attached to the connection; the custom retriever supplies it.
    var (handler, _) = await HandlerTestHarness.CreateAsync(options, token);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
  }

  [Test]
  public async Task Should_Succeed_When_CnfHasAdditionalMembersBesidesThumbprint()
  {
    var options = BindingOptions(new OpenIdServerMock());

    // cnf carries x5t#S256 alongside another (non-string) member; binding must still validate.
    var token = OpenIdServerMock.CreateAccessToken(new List<Claim>
    {
      new("cnf", $"{{\"x5t#S256\":\"{OpenIdServerMock.MtlsThumbprint}\",\"jwk\":{{\"kty\":\"RSA\"}}}}", JsonClaimValueTypes.Json)
    });

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, token, clientCertificate: OpenIdServerMock.MtlsClientCert);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
  }

  [Test]
  public async Task Should_ValidateBinding_OnIntrospectedToken()
  {
    var bindingValidated = false;
    var server = new OpenIdServerMock();
    server.SetupIntrospection(authType: "client_secret_post");

    var options = OpaqueBindingOptions(server, o => o.Events.OnCertificateBindingValidated = _ =>
    {
      bindingValidated = true;
      return Task.CompletedTask;
    });

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, "opaque-bound-token", clientCertificate: OpenIdServerMock.MtlsClientCert);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");

    bindingValidated.ShouldBeTrue();
  }

  [Test]
  public async Task Should_Fail_When_IntrospectedTokenCertificateDoesNotMatch()
  {
    var server = new OpenIdServerMock();
    server.SetupIntrospection(authType: "client_secret_post");

    var options = OpaqueBindingOptions(server);

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, "opaque-bound-token-mismatch", clientCertificate: OpenIdServerMock.PrivateKeyCert);

    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeFalse();

    result.Failure!.Message.ShouldBe("The certificate hash in the access token does not match the presented client certificate (certificate binding validation failed)");
  }

  [Test]
  public async Task Should_ValidateBinding_OnCachedClaims()
  {
    var cache = new IntrospectionCacheMock();
    const string token = "opaque-bound-cached";

    // First request introspects and caches the claims (including cnf).
    var server1 = new OpenIdServerMock();
    server1.SetupIntrospection(authType: "client_secret_post");
    var options1 = OpaqueBindingOptions(server1, o => o.EnableCaching = true);
    var (handler1, _) = await HandlerTestHarness.CreateAsync(options1, token, cache, OpenIdServerMock.MtlsClientCert);
    (await handler1.AuthenticateAsync()).Succeeded.ShouldBeTrue();
    cache.SetCount.ShouldBe(1);

    // Second request: no introspection endpoint configured — success can only come from the cache,
    // and the binding-validated event proves the cached-claims binding block ran.
    var bindingValidated = false;
    var server2 = new OpenIdServerMock();

    var options2 = OpaqueBindingOptions(server2, o =>
    {
      o.EnableCaching = true;

      o.Events.OnCertificateBindingValidated = _ =>
      {
        bindingValidated = true;
        return Task.CompletedTask;
      };
    });

    var (handler2, _) = await HandlerTestHarness.CreateAsync(options2, token, cache, OpenIdServerMock.MtlsClientCert);
    var result = await handler2.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
    bindingValidated.ShouldBeTrue();
    cache.SetCount.ShouldBe(1); // not written again
    server2.VerifyIntrospectionCalled(Times.Never());
  }

  [Test]
  public async Task Should_Fail_When_CachedClaimsCertificateDoesNotMatch()
  {
    var cache = new IntrospectionCacheMock();
    const string token = "opaque-bound-cached-mismatch";

    // First request introspects with the bound certificate and caches the (active) claims.
    var server1 = new OpenIdServerMock();
    server1.SetupIntrospection(authType: "client_secret_post");
    var options1 = OpaqueBindingOptions(server1, o => o.EnableCaching = true);
    var (handler1, _) = await HandlerTestHarness.CreateAsync(options1, token, cache, OpenIdServerMock.MtlsClientCert);
    (await handler1.AuthenticateAsync()).Succeeded.ShouldBeTrue();

    // Second request replays the token from the cache with a DIFFERENT certificate — the cached
    // active claims must not bypass certificate binding.
    var server2 = new OpenIdServerMock();
    var options2 = OpaqueBindingOptions(server2, o => o.EnableCaching = true);
    var (handler2, _) = await HandlerTestHarness.CreateAsync(options2, token, cache, OpenIdServerMock.PrivateKeyCert);
    var result = await handler2.AuthenticateAsync();

    result.Succeeded.ShouldBeFalse();

    result.Failure!.Message.ShouldBe("The certificate hash in the access token does not match the presented client certificate (certificate binding validation failed)");
    server2.VerifyIntrospectionCalled(Times.Never());
  }
}
