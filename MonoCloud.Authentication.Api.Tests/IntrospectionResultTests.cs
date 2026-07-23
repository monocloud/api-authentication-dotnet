namespace MonoCloud.Authentication.Api.Tests;

public class IntrospectionResultTests
{
  private static IntrospectionResult Parse(string json) => new(JsonDocument.Parse(json).RootElement);

  [Test]
  public void Should_BeActive_When_ActiveIsTrue()
  {
    Parse("""{"active":true}""").IsActive.ShouldBeTrue();
  }

  [Test]
  public void Should_BeInactive_When_ActiveIsFalse()
  {
    Parse("""{"active":false}""").IsActive.ShouldBeFalse();
  }

  [Test]
  public void Should_BeInactive_When_ActiveIsMissing()
  {
    Parse("""{"sub":"123"}""").IsActive.ShouldBeFalse();
  }

  [Test]
  public void Should_SplitSpaceDelimitedScopeString()
  {
    var result = Parse("""{"active":true,"scope":"openid resource profile"}""");

    result.Claims.Where(c => c.Type == "scope").Select(c => c.Value).ShouldBe(["openid", "resource", "profile"]);
  }

  [Test]
  public void Should_HandleScopeAsArray()
  {
    var result = Parse("""{"active":true,"scope":["openid","resource"]}""");

    result.Claims.Where(c => c.Type == "scope").Select(c => c.Value).ShouldBe(["openid", "resource"]);
  }

  [Test]
  public void Should_CreateOneClaimPerArrayElement()
  {
    var result = Parse("""{"active":true,"roles":["admin","editor"]}""");

    var roles = result.Claims.Where(c => c.Type == "roles").ToList();
    roles.Select(c => c.Value).ShouldBe(["admin", "editor"]);
  }

  [Test]
  public void Should_CreateJsonClaim_ForObjectValues()
  {
    var result = Parse("""{"active":true,"address":{"city":"London"}}""");

    var address = result.Claims.Single(c => c.Type == "address");
    address.ValueType.ShouldBe(JsonClaimValueTypes.Json);
    address.Value.ShouldBe("""{"city":"London"}""");
  }

  [Test]
  public void Should_PropagateIssuerToClaims()
  {
    var result = Parse("""{"active":true,"iss":"https://localhost","sub":"123","scope":"openid"}""");

    result.Claims.Single(c => c.Type == "sub").Issuer.ShouldBe("https://localhost");
    result.Claims.Single(c => c.Type == "scope").Issuer.ShouldBe("https://localhost");
  }

  [Test]
  public void Should_SkipNonStringScopeArrayElements()
  {
    // A scope array carrying non-string / null elements must not abort parsing of an active token.
    var result = Parse("""{"active":true,"scope":["openid",1,null,"resource"]}""");

    result.IsActive.ShouldBeTrue();
    result.Claims.Where(c => c.Type == "scope").Select(c => c.Value)
        .ShouldBe(["openid", "resource"]);
  }

  [Test]
  public void Should_NotThrow_When_IssuerIsNonString()
  {
    // A non-string `iss` must not abort parsing of an otherwise valid active token.
    var result = Parse("""{"active":true,"iss":123,"sub":"1"}""");

    result.IsActive.ShouldBeTrue();
    result.Claims.ShouldContain(c => c.Type == "sub" && c.Value == "1");
  }
}
