namespace MonoCloud.Authentication.Api.Tests;

public class UtilsTests
{
  private static string ExpectedHash(string input) =>
      Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(input)));

  private static Claim ExpClaim(DateTimeOffset when) => new("exp", when.ToUnixTimeSeconds().ToString());

  [Test]
  public void CacheKeyGenerator_PrependsPrefixToTokenHash()
  {
    var options = new MonoCloudAuthenticationOptions
    {
      CacheKeyPrefix = "prefix:",
      SchemeName = "MyScheme"
    };

    var key = Utils.CacheKeyGenerator(options, "the-token");

    key.ShouldBe($"prefix:{ExpectedHash("MyScheme|the-token")}");
  }

  [Test]
  public void CacheKeyGenerator_DiffersByScheme()
  {
    var a = new MonoCloudAuthenticationOptions { SchemeName = "scheme-a" };
    var b = new MonoCloudAuthenticationOptions { SchemeName = "scheme-b" };

    // The same token must not collide across distinct authentication schemes.
    Utils.CacheKeyGenerator(a, "tok").ShouldNotBe(Utils.CacheKeyGenerator(b, "tok"));
  }

  [Test]
  public void CacheKeyGenerator_IsDeterministicAndTokenDependent()
  {
    var options = new MonoCloudAuthenticationOptions();

    Utils.CacheKeyGenerator(options, "a").ShouldBe(Utils.CacheKeyGenerator(options, "a"));
    Utils.CacheKeyGenerator(options, "a").ShouldNotBe(Utils.CacheKeyGenerator(options, "b"));
  }

  [Test]
  public void NormalizeGroupClaims_ExpandsStringArray()
  {
    var claims = new List<Claim>
        {
            new("groups", """["admin","editor"]""", JsonClaimValueTypes.JsonArray)
        };

    claims.NormalizeGroupClaims("groups");

    claims.ShouldNotContain(c => c.ValueType == JsonClaimValueTypes.JsonArray);
    claims.Where(c => c.Type == "groups").Select(c => c.Value).ShouldBe(new[] { "admin", "editor" });
  }

  [Test]
  public void NormalizeGroupClaims_ExpandsIdAndNameForObjectArray()
  {
    var claims = new List<Claim>
        {
            new("groups", """[{"id":"adminId","name":"admin"}]""", JsonClaimValueTypes.JsonArray)
        };

    claims.NormalizeGroupClaims("groups");

    var values = claims.Where(c => c.Type == "groups").Select(c => c.Value).ToList();
    values.ShouldBe(new[] { "adminId", "admin" });
  }

  [Test]
  public void NormalizeGroupClaims_DoesNothing_When_NoMatchingArrayClaim()
  {
    var claims = new List<Claim> { new("sub", "123") };

    claims.NormalizeGroupClaims("groups");

    claims.Count.ShouldBe(1);
    claims[0].Type.ShouldBe("sub");
  }

  [Test]
  public void NormalizeGroupClaims_SkipsObjectWithNullIdOrName()
  {
    // A group object with a null id/name must be skipped, not throw an NRE.
    var claims = new List<Claim>
        {
            new("groups", """[{"id":null,"name":"admin"}]""", JsonClaimValueTypes.JsonArray)
        };

    Should.NotThrow(() => claims.NormalizeGroupClaims("groups"));

    claims.ShouldNotContain(c => c.Type == "groups");
  }

  [Test]
  public void NormalizeGroupClaims_ExpandsObjectWithExtraMembers()
  {
    // Objects carrying members beyond id/name must still expand (the Count == 2 constraint was removed).
    var claims = new List<Claim>
        {
            new("groups", """[{"id":"adminId","name":"admin","description":"Administrators"}]""", JsonClaimValueTypes.JsonArray)
        };

    claims.NormalizeGroupClaims("groups");

    claims.Where(c => c.Type == "groups").Select(c => c.Value).ShouldBe(new[] { "adminId", "admin" });
  }

  [Test]
  public async Task SetClaims_Then_GetClaims_RoundTrips()
  {
    var cache = new IntrospectionCacheMock();
    var options = new MonoCloudAuthenticationOptions();
    var claims = new List<Claim> { new("sub", "123"), ExpClaim(DateTimeOffset.UtcNow.AddHours(1)) };

    await cache.SetClaimsAsync(options, "tok", claims, TimeSpan.FromMinutes(5), NullLogger.Instance, default);

    cache.SetCount.ShouldBe(1);

    var read = await cache.GetClaimsAsync(options, "tok", default);
    read.ShouldNotBeNull();
    read!.Single(c => c.Type == "sub").Value.ShouldBe("123");
  }

  [Test]
  public async Task SetClaims_CachesForFullDuration_When_NoExpClaim()
  {
    // An introspection result without an exp claim (e.g. an inactive token: {"active":false})
    // must still be cached, for the full configured duration.
    var cache = new IntrospectionCacheMock();
    var options = new MonoCloudAuthenticationOptions();

    await cache.SetClaimsAsync(options, "tok", new List<Claim> { new("active", "false") }, TimeSpan.FromMinutes(5), NullLogger.Instance, default);

    cache.SetCount.ShouldBe(1);
    cache.LastExpiresIn!.Value.ShouldBe(TimeSpan.FromMinutes(5));
    (await cache.GetClaimsAsync(options, "tok", default)).ShouldNotBeNull();
  }

  [Test]
  public async Task SetClaims_CachesForFullDuration_When_ExpIsNotNumeric()
  {
    // A non-numeric exp must not throw; it falls back to caching for the configured duration.
    var cache = new IntrospectionCacheMock();
    var options = new MonoCloudAuthenticationOptions();
    var claims = new List<Claim> { new("sub", "123"), new("exp", "not-a-number") };

    await cache.SetClaimsAsync(options, "tok", claims, TimeSpan.FromMinutes(5), NullLogger.Instance, default);

    cache.SetCount.ShouldBe(1);
    cache.LastExpiresIn!.Value.ShouldBe(TimeSpan.FromMinutes(5));
  }

  [Test]
  public async Task SetClaims_DoesNotCache_When_TokenAlreadyExpired()
  {
    var cache = new IntrospectionCacheMock();
    var options = new MonoCloudAuthenticationOptions();
    var claims = new List<Claim> { ExpClaim(DateTimeOffset.UtcNow.AddMinutes(-1)) };

    await cache.SetClaimsAsync(options, "tok", claims, TimeSpan.FromMinutes(5), NullLogger.Instance, default);

    cache.SetCount.ShouldBe(0);
  }

  [Test]
  public async Task SetClaims_CapsTtlToRemainingTokenLifetime()
  {
    var cache = new IntrospectionCacheMock();
    var options = new MonoCloudAuthenticationOptions();
    // Token expires in ~2 minutes; requested cache duration is 5 minutes.
    var claims = new List<Claim> { ExpClaim(DateTimeOffset.UtcNow.AddMinutes(2)) };

    await cache.SetClaimsAsync(options, "tok", claims, TimeSpan.FromMinutes(5), NullLogger.Instance, default);

    cache.LastExpiresIn!.Value.ShouldBeLessThanOrEqualTo(TimeSpan.FromMinutes(2));
    cache.LastExpiresIn!.Value.ShouldBeGreaterThan(TimeSpan.FromMinutes(1));
  }

  [Test]
  public async Task SetClaims_UsesFullDuration_When_TokenOutlivesIt()
  {
    var cache = new IntrospectionCacheMock();
    var options = new MonoCloudAuthenticationOptions();
    var claims = new List<Claim> { ExpClaim(DateTimeOffset.UtcNow.AddHours(1)) };

    await cache.SetClaimsAsync(options, "tok", claims, TimeSpan.FromMinutes(5), NullLogger.Instance, default);

    cache.LastExpiresIn!.Value.ShouldBe(TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(5));
  }
}
