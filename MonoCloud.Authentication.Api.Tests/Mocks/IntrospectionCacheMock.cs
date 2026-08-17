namespace MonoCloud.Authentication.Api.Tests.Mocks;

public class IntrospectionCacheMock : IIntrospectionCache
{
  private readonly ConcurrentDictionary<string, string> _cache = new();

  public int SetCount { get; private set; }

  public int DeleteCount { get; private set; }

  public TimeSpan? LastExpiresIn { get; private set; }

  public bool ThrowOnGet { get; set; }

  public bool ThrowOnSet { get; set; }

  public Task<string?> GetAsync(string key, CancellationToken cancellationToken = default)
  {
    if (ThrowOnGet)
    {
      throw new InvalidOperationException("[Test] Cache is unavailable");
    }

    _cache.TryGetValue(key, out var value);
    return Task.FromResult(value);
  }

  public Task SetAsync(string key, string value, TimeSpan expiresIn, CancellationToken cancellationToken = default)
  {
    if (ThrowOnSet)
    {
      throw new InvalidOperationException("[Test] Cache is unavailable");
    }

    SetCount++;
    LastExpiresIn = expiresIn;
    _cache[key] = value;
    return Task.CompletedTask;
  }

  public Task DeleteAsync(string key, CancellationToken cancellationToken = default)
  {
    DeleteCount++;
    _cache.TryRemove(key, out _);
    return Task.CompletedTask;
  }
}
