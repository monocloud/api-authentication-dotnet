namespace MonoCloud.Authentication.Api.Tests.Mocks;

public class ConfigurationManagerMock(OpenIdConnectConfiguration configuration) : IConfigurationManager<OpenIdConnectConfiguration>
{
  public int RefreshRequests { get; private set; }

  public Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel) => Task.FromResult(configuration);

  public void RequestRefresh() => RefreshRequests++;
}
