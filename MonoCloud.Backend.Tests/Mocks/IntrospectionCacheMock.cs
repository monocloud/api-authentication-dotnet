namespace MonoCloud.Backend.Tests.Mocks;

public class IntrospectionCacheMock : IIntrospectionCache
{
  private readonly ConcurrentDictionary<string, string> _cache = new();

  /// <summary>Number of times <see cref="SetAsync"/> was invoked.</summary>
  public int SetCount { get; private set; }

  /// <summary>The expiry passed to the most recent <see cref="SetAsync"/> call.</summary>
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
