namespace MonoCloud.Authentication.Api.Tests;

/// <summary>
/// Covers the mutual-TLS (<see cref="TlsAuth"/>) introspection path, where the introspection endpoint is
/// resolved from the discovery document's <c>mtls_endpoint_aliases</c> (or <c>mtls_additional_endpoint_aliases</c>).
/// </summary>
public class MtlsIntrospectionTests
{
  private const string OpaqueToken = "opaque-mtls-token";

  private static MonoCloudAuthenticationOptions TlsOptions(OpenIdServerMock server, IMonoCloudClientAuth clientAuth)
  {
    return new MonoCloudAuthenticationOptions
    {
      TenantDomain = OpenIdServerMock.Issuer,
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
    server.SetupIntrospection(authType: "none", endpoint: OpenIdServerMock.MtlsIntrospectionEndpoint);

    var options = TlsOptions(server, new TlsAuth());

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
  }

  [Test]
  public async Task Should_UseCustomTrustStoreEndpoint_When_TlsAuthSpecifiesTrustStore()
  {
    var server = new OpenIdServerMock();
    server.SetupDiscovery();
    server.SetupJwks();
    server.SetupIntrospection(authType: "none", endpoint: OpenIdServerMock.CustomTrustStoreMtlsIntrospectionEndpoint);

    var options = TlsOptions(server, new TlsAuth(trustStore: "id"));

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeTrue(result.Failure?.ToString() ?? "no failure");
  }

  [Test]
  public async Task Should_Fail_When_MtlsEndpointAliasIsMissing()
  {
    var server = new OpenIdServerMock();
    server.SetupDiscovery(includeMtls: false);
    server.SetupJwks();
    server.SetupIntrospection(authType: "none", endpoint: OpenIdServerMock.MtlsIntrospectionEndpoint);

    var options = TlsOptions(server, new TlsAuth());

    var (handler, _) = await HandlerTestHarness.CreateAsync(options, OpaqueToken);
    var result = await handler.AuthenticateAsync();

    result.Succeeded.ShouldBeFalse();
    result.Failure!.Message.ShouldBe("Introspection failed");
  }
}
