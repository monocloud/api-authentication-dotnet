namespace MonoCloud.Authentication.Api;

/// <summary>
/// Assigns the <see cref="TimeProvider"/> registered in the service collection to the scheme options.
/// </summary>
/// <remarks>
/// Replicates the post-configuration the framework applies to every scheme registered through
/// <c>AddScheme</c>. Since the MonoCloud scheme is registered manually (see
/// <see cref="MonoCloudAuthenticationExtension"/>), it has to be supplied here so a substituted
/// <see cref="System.TimeProvider"/> reaches the handler's clock exactly as it does for
/// framework-registered schemes. Note that JWT lifetime validation happens inside
/// Microsoft.IdentityModel, which uses its own clock — the same limitation stock <c>AddJwtBearer</c> has.
/// </remarks>
internal sealed class PostConfigureMonoCloudAuthenticationTimeProvider(TimeProvider timeProvider) : IPostConfigureOptions<MonoCloudAuthenticationOptions>
{
  public void PostConfigure(string? name, MonoCloudAuthenticationOptions options)
  {
    options.TimeProvider ??= timeProvider;
  }
}
