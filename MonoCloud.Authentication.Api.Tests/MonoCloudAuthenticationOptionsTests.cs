namespace MonoCloud.Authentication.Api.Tests;

public class MonoCloudAuthenticationOptionsTests
{
  private static JsonWebTokenHandler TokenHandlerOf(MonoCloudAuthenticationOptions options) => options.TokenHandlers.OfType<JsonWebTokenHandler>().Single();

  [Test]
  public void MapInboundClaims_DefaultsToTrue_AndReachesTheTokenHandler()
  {
    var options = new MonoCloudAuthenticationOptions();

    options.MapInboundClaims.ShouldBeTrue();
    TokenHandlerOf(options).MapInboundClaims.ShouldBeTrue();
  }

  [Test]
  public void MapInboundClaims_Setter_SyncsTheTokenHandler()
  {
    var options = new MonoCloudAuthenticationOptions { MapInboundClaims = false };

    TokenHandlerOf(options).MapInboundClaims.ShouldBeFalse();

    options.MapInboundClaims = true;
    TokenHandlerOf(options).MapInboundClaims.ShouldBeTrue();
  }

  [Test]
  public void Events_DefaultsToMonoCloudEvents()
  {
    var options = new MonoCloudAuthenticationOptions();

    Should.NotThrow(() => options.Events).ShouldBeOfType<MonoCloudAuthenticationEvents>();
  }

  [Test]
  public void Options_InheritJwtBearerDefaults()
  {
    var options = new MonoCloudAuthenticationOptions();

    options.SaveToken.ShouldBeTrue();
    options.RefreshOnIssuerKeyNotFound.ShouldBeTrue();
    options.IncludeErrorDetails.ShouldBeTrue();
    options.RequireHttpsMetadata.ShouldBeTrue();
  }
}
