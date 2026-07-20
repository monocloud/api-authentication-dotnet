namespace MonoCloud.Authentication.Api.Shared;

internal class IntrospectionResult
{
  public IntrospectionResult(JsonElement response)
  {
    string? issuer = null;

    if (response.TryGetProperty("iss", out var issuerValue) && issuerValue.ValueKind is JsonValueKind.String)
    {
      issuer = issuerValue.GetString();
    }

    var claims = new List<Claim>();

    if (response.TryGetProperty("scope", out var scopeValue) && scopeValue.ValueKind is JsonValueKind.String or JsonValueKind.Array)
    {
      var scopes = new List<string>();

      if (scopeValue.ValueKind is JsonValueKind.Array)
      {
        scopes.AddRange(scopeValue.EnumerateArray()
            .Where(scope => scope.ValueKind is JsonValueKind.String)
            .Select(scope => scope.GetString()!));
      }
      else
      {
        scopes.AddRange(scopeValue.GetString()!.Split(' ', StringSplitOptions.RemoveEmptyEntries));
      }

      foreach (var scope in scopes)
      {
        claims.Add(new Claim("scope", scope, ClaimValueTypes.String, issuer));
      }
    }

    foreach (var obj in response.EnumerateObject().Where(x => x.Name != "scope"))
    {
      switch (obj.Value.ValueKind)
      {
        case JsonValueKind.Array:
        {
          foreach (var item in obj.Value.EnumerateArray())
          {
            claims.Add(new Claim(obj.Name, Stringify(item), ClaimValueTypes.String, issuer));
          }
          break;
        }
        case JsonValueKind.Object:
        {
          claims.Add(new Claim(obj.Name, Stringify(obj.Value), JsonClaimValueTypes.Json, issuer));
          break;
        }
        default:
        {
          claims.Add(new Claim(obj.Name, Stringify(obj.Value), ClaimValueTypes.String, issuer));
          break;
        }
      }
    }

    var active = false;
    if (response.TryGetProperty("active", out var activeValue) && activeValue.ValueKind is JsonValueKind.True or JsonValueKind.False)
    {
      active = activeValue.GetBoolean();
    }

    Claims = claims;
    IsActive = active;
  }

  public bool IsActive { get; init; }

  public IEnumerable<Claim> Claims { get; init; }

  private static string Stringify(JsonElement item) => item.ValueKind == JsonValueKind.String ? item.ToString() : item.GetRawText();
}
