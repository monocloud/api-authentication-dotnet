namespace MonoCloud.Authentication.Api.Tests;

public class MonoCloudAuthenticationOptionsTests
{
  [Test]
  public void MapInboundClaims_DefaultsToTrue_AndReachesTheTokenHandler()
  {
    var options = new MonoCloudAuthenticationOptions();

    options.MapInboundClaims.ShouldBeTrue();
    options.JwtTokenHandler.MapInboundClaims.ShouldBeTrue();
  }

  [Test]
  public void MapInboundClaims_Setter_SyncsTheTokenHandler()
  {
    var options = new MonoCloudAuthenticationOptions { MapInboundClaims = false };

    options.JwtTokenHandler.MapInboundClaims.ShouldBeFalse();

    options.MapInboundClaims = true;
    options.JwtTokenHandler.MapInboundClaims.ShouldBeTrue();
  }
}
