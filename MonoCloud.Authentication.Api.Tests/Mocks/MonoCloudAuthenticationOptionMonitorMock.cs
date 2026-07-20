namespace MonoCloud.Authentication.Api.Tests.Mocks;

public class MonoCloudAuthenticationOptionMonitorMock(MonoCloudAuthenticationOptions options)
    : IOptionsMonitor<MonoCloudAuthenticationOptions>
{
  public MonoCloudAuthenticationOptions Get(string? name) => options;

  public IDisposable? OnChange(Action<MonoCloudAuthenticationOptions, string?> listener) => null;

  public MonoCloudAuthenticationOptions CurrentValue => options;
}
