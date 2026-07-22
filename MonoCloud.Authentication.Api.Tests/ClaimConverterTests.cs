namespace MonoCloud.Authentication.Api.Tests;

public class ClaimConverterTests
{
  private static readonly JsonSerializerOptions Options = new() { Converters = { new ClaimConverter() } };

  [Test]
  public void Should_SerializeClaim_ToTypeAndValue()
  {
    var json = JsonSerializer.Serialize(new Claim("sub", "123"), Options);

    json.ShouldBe("""{"Type":"sub","Value":"123"}""");
  }

  [Test]
  public void Should_DeserializeClaim_FromTypeAndValue()
  {
    var claim = JsonSerializer.Deserialize<Claim>("""{"Type":"scope","Value":"openid"}""", Options)!;

    claim.Type.ShouldBe("scope");
    claim.Value.ShouldBe("openid");
  }

  [Test]
  public void Should_RoundTripListOfClaims()
  {
    var claims = new List<Claim> { new("sub", "123"), new("scope", "openid") };

    var json = JsonSerializer.Serialize(claims, Options);
    var back = JsonSerializer.Deserialize<List<Claim>>(json, Options)!;

    back.Count.ShouldBe(2);
    back[0].Type.ShouldBe("sub");
    back[0].Value.ShouldBe("123");
    back[1].Type.ShouldBe("scope");
    back[1].Value.ShouldBe("openid");
  }
}
