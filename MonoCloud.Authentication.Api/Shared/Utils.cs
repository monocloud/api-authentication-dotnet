namespace MonoCloud.Authentication.Api.Shared;

internal static class Utils
{
  private static readonly JsonSerializerOptions Options = new()
  {
    IgnoreReadOnlyFields = true,
    IgnoreReadOnlyProperties = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    Converters = { new ClaimConverter() }
  };

  public static async Task<IList<Claim>?> GetClaimsAsync(this IIntrospectionCache cache, MonoCloudAuthenticationOptions options, string token, CancellationToken cancellationToken)
  {
    var cacheKey = options.CacheKeyGenerator(options, token);
    var json = await cache.GetAsync(cacheKey, cancellationToken).ConfigureAwait(false);

    if (json == null)
    {
      return null;
    }

    return JsonSerializer.Deserialize<IList<Claim>>(json, Options);
  }

  public static async Task SetClaimsAsync(this IIntrospectionCache cache, MonoCloudAuthenticationOptions options, string token, IList<Claim> claims, TimeSpan duration, ILogger logger, CancellationToken cancellationToken)
  {
    var now = DateTimeOffset.UtcNow;
    var ttl = duration;

    var expClaim = claims.FirstOrDefault(c => c.Type == "exp");
    if (expClaim != null && long.TryParse(expClaim.Value, out var expSeconds))
    {
      var tokenExpiration = DateTimeOffset.FromUnixTimeSeconds(expSeconds);
      logger.LogDebug("Token will expire in {Expiration}", tokenExpiration);

      if (tokenExpiration <= now)
      {
        return;
      }

      var desiredExpiration = now.Add(duration);
      var remainingTokenLife = tokenExpiration - now;
      if (tokenExpiration <= desiredExpiration)
      {
        ttl = remainingTokenLife;
      }
    }

    var json = JsonSerializer.Serialize(claims, Options);

    logger.LogDebug("Setting cache to expire in {TTL}", ttl);

    var cacheKey = options.CacheKeyGenerator(options, token);

    await cache.SetAsync(cacheKey, json, ttl, cancellationToken).ConfigureAwait(false);
  }

  internal static Func<MonoCloudAuthenticationOptions, string, string> CacheKeyGenerator => (options, token) =>
      $"{options.CacheKeyPrefix}{$"{options.SchemeName}|{token}".Sha256()}";

  private static string Sha256(this string input)
  {
    if (string.IsNullOrEmpty(input)) return string.Empty;
    var bytes = Encoding.UTF8.GetBytes(input);
    var hash = SHA256.HashData(bytes);
    return Convert.ToBase64String(hash);
  }

  internal static long ToUnixTimeStamp(this DateTime dateTime) => new DateTimeOffset(dateTime.ToUniversalTime()).ToUnixTimeSeconds();

  internal static bool HasNormalizableScopeClaims(this IEnumerable<Claim> claims) => claims.Any(c => c.Type == "scope" && c.Value.Contains(' '));

  internal static void NormalizeScopeClaims(this IList<Claim> claims)
  {
    foreach (var scopeClaim in claims.Where(c => c.Type == "scope" && c.Value.Contains(' ')).ToList())
    {
      claims.Remove(scopeClaim);

      foreach (var scope in scopeClaim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
      {
        claims.Add(new Claim("scope", scope, ClaimValueTypes.String, scopeClaim.Issuer));
      }
    }
  }

  internal static bool HasNormalizableGroupClaims(this IEnumerable<Claim> claims, string claimType) => claims.Any(c => c.Type == claimType && (c.ValueType == JsonClaimValueTypes.JsonArray || (c.Value.Length > 0 && c.Value[0] == '{')));

  internal static void NormalizeGroupClaims(this IList<Claim> claims, string claimType)
  {
    var groups = claims.FirstOrDefault(c => c.Type == claimType && c.ValueType == JsonClaimValueTypes.JsonArray);

    if (groups != null)
    {
      claims.RemoveAt(claims.IndexOf(groups));

      var groupsArray = JsonNode.Parse(groups.Value)!.AsArray();

      foreach (var group in groupsArray)
      {
        if (group is JsonValue groupValue && groupValue.GetValue<JsonElement>().ValueKind == JsonValueKind.String)
        {
          claims.Add(new Claim(claimType, groupValue.GetValue<string>()));
        }
        else if (group is JsonObject groupObject && TryGetGroupIdAndName(groupObject, out var id, out var name))
        {
          claims.Add(new Claim(claimType, id));
          claims.Add(new Claim(claimType, name));
        }
      }

      return;
    }

    foreach (var groupClaim in claims.Where(c => c.Type == claimType).ToList())
    {
      if (groupClaim.Value.Length == 0 || groupClaim.Value[0] != '{')
      {
        continue;
      }

      JsonObject? groupObject;
      try
      {
        groupObject = JsonNode.Parse(groupClaim.Value) as JsonObject;
      }
      catch (JsonException)
      {
        continue;
      }

      if (groupObject != null && TryGetGroupIdAndName(groupObject, out var id, out var name))
      {
        var index = claims.IndexOf(groupClaim);
        claims.RemoveAt(index);
        claims.Insert(index, new Claim(claimType, id));
        claims.Insert(index + 1, new Claim(claimType, name));
      }
    }
  }

  private static bool TryGetGroupIdAndName(JsonObject groupObject, out string id, out string name)
  {
    id = string.Empty;
    name = string.Empty;

    if (groupObject["id"] is JsonValue idValue && idValue.TryGetValue<string>(out var idResult) &&
        groupObject["name"] is JsonValue nameValue && nameValue.TryGetValue<string>(out var nameResult))
    {
      id = idResult;
      name = nameResult;
      return true;
    }

    return false;
  }
}
