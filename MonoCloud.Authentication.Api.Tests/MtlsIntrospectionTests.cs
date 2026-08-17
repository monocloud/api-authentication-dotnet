namespace MonoCloud.Authentication.Api.Tests;

public class MtlsIntrospectionTests
{
  private const string OpaqueToken = "opaque-mtls-token";

  private static MonoCloudAuthenticationOptions TlsOptions(OpenIdServerMock server, IMonoCloudClientAuth clientAuth)
  {
    return new MonoCloudAuthenticationOptions
    {
      Authority = OpenIdServerMock.Issuer,
      ClientId = OpenIdServerMock.ClientId,
      ClientAuth = clientAuth,
      HttpClient = server.Build()
    };
  }

  [Test]
  public async Task Should_UseMtlsIntrospectionEndpoint_When_TlsAuthWithDefaultTrustStore()
  {
    var server = new OpenIdServerMock();
    server.SetupDiscovery();
    server.SetupJwks();
    server.SetupIntrospection(authType: "tls_client_auth", endpoint: OpenIdServerMock.MtlsIntrospectionEndpoint);

    var options = TlsOptions(server, new TlsAuth());

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
    server.VerifyIntrospectionCalled(endpoint: OpenIdServerMock.MtlsIntrospectionEndpoint);
    server.VerifyIntrospectionCalled(Times.Never());
  }

  [Test]
  public async Task Should_UseCustomTrustStoreEndpoint_When_TlsAuthSpecifiesTrustStore()
  {
    var server = new OpenIdServerMock();
    server.SetupDiscovery();
    server.SetupJwks();
    server.SetupIntrospection(authType: "tls_client_auth", endpoint: OpenIdServerMock.CustomTrustStoreMtlsIntrospectionEndpoint);

    var options = TlsOptions(server, new TlsAuth(trustStore: "id"));

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
    server.VerifyIntrospectionCalled(endpoint: OpenIdServerMock.CustomTrustStoreMtlsIntrospectionEndpoint);
    server.VerifyIntrospectionCalled(Times.Never(), OpenIdServerMock.MtlsIntrospectionEndpoint);
  }

  [Test]
  public async Task Should_UseMtlsIntrospectionEndpoint_When_SpiffeX509Auth()
  {
    var server = new OpenIdServerMock();
    server.SetupDiscovery();
    server.SetupJwks();
    server.SetupIntrospection(authType: "spiffe_x509", endpoint: OpenIdServerMock.MtlsIntrospectionEndpoint);

    var options = TlsOptions(server, new SpiffeX509Auth());

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
    server.VerifyIntrospectionCalled(endpoint: OpenIdServerMock.MtlsIntrospectionEndpoint);
    server.VerifyIntrospectionCalled(Times.Never());
  }

  [Test]
  public async Task Should_UseCustomTrustStoreEndpoint_When_SpiffeX509AuthSpecifiesTrustStore()
  {
    var server = new OpenIdServerMock();
    server.SetupDiscovery();
    server.SetupJwks();
    server.SetupIntrospection(authType: "spiffe_x509", endpoint: OpenIdServerMock.CustomTrustStoreMtlsIntrospectionEndpoint);

    var options = TlsOptions(server, new SpiffeX509Auth(trustStore: "id"));

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
    server.VerifyIntrospectionCalled(endpoint: OpenIdServerMock.CustomTrustStoreMtlsIntrospectionEndpoint);
    server.VerifyIntrospectionCalled(Times.Never(), OpenIdServerMock.MtlsIntrospectionEndpoint);
  }

  [Test]
  public async Task Should_Throw_When_MtlsEndpointAliasIsMissing()
  {
    var server = new OpenIdServerMock();
    server.SetupDiscovery(includeMtls: false);
    server.SetupJwks();
    server.SetupIntrospection(authType: "tls_client_auth", endpoint: OpenIdServerMock.MtlsIntrospectionEndpoint);

    var options = TlsOptions(server, new TlsAuth());

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);

    var exception = await Should.ThrowAsync<InvalidOperationException>(() => handler.AuthenticateAsync());
    exception.Message.ShouldContain("mTLS introspection endpoint alias");

    server.VerifyIntrospectionCalled(Times.Never(), OpenIdServerMock.MtlsIntrospectionEndpoint);
    server.VerifyIntrospectionCalled(Times.Never());
  }
}
