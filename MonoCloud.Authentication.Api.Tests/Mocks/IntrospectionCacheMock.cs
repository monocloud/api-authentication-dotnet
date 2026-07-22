namespace MonoCloud.Authentication.Api.Tests.Mocks;

public class IntrospectionCacheMock : IIntrospectionCache
{
  private readonly ConcurrentDictionary<string, string> _cache = new();

  public int SetCount { get; private set; }

  public TimeSpan? LastExpiresIn { get; private set; }

  public Task<string?> GetAsync(string key, CancellationToken cancellationToken = default)
  {
    _cache.TryGetValue(key, out var value);
    return Task.FromResult(value);
  }

  public Task SetAsync(string key, string value, TimeSpan expiresIn, CancellationToken cancellationToken = default)
  {
    SetCount++;
    LastExpiresIn = expiresIn;
    _cache[key] = value;
    return Task.CompletedTask;
  }
}
