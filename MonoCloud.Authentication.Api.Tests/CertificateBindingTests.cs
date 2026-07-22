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

  [Test]
  public async Task Should_Succeed_When_CertificateMatchesBinding()
  {
    var bindingValidated = false;
    var options = BindingOptions(new OpenIdServerMock(),
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
    var token = OpenIdServerMock.CreateAccessToken(excludeClaims: new[] { "cnf" });

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
    var token = OpenIdServerMock.CreateAccessToken(new List<Claim>
        {
            new("cnf", "{\"foo\":\"bar\"}", JsonClaimValueTypes.Json)
        });

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
    result.Failure!.Message.ShouldBe("The certificate hash in the access token does not match the presented client certificate (certificate binding validation failed)");
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
        o => o.CertificateRetriever = _ => Task.FromResult<System.Security.Cryptography.X509Certificates.X509Certificate2?>(OpenIdServerMock.MtlsClientCert));

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
}
