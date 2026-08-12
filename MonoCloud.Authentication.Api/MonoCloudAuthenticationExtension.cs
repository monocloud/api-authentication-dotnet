namespace MonoCloud.Authentication.Api;

/// <summary>
/// Extension methods for registering the MonoCloud authentication handler with an <see cref="AuthenticationBuilder"/>.
/// </summary>
public static class MonoCloudAuthenticationExtension
{
  /// <summary>
  /// Adds the MonoCloud authentication handler to the specified <see cref="AuthenticationBuilder"/>
  /// using the default authentication scheme.
  /// </summary>
  /// <param name="builder">The <see cref="AuthenticationBuilder"/> to add the handler to.</param>
  /// <returns>The <see cref="AuthenticationBuilder"/> so that additional schemes can be chained.</returns>
  public static AuthenticationBuilder AddMonoCloudAuthentication(this AuthenticationBuilder builder) => builder.AddMonoCloudAuthentication(MonoCloudAuthenticationDefaults.AuthenticationScheme, null);
  /// <summary>
  /// Adds the MonoCloud authentication handler to the specified <see cref="AuthenticationBuilder"/>
  /// using a custom authentication scheme.
  /// </summary>
  /// <param name="builder">The <see cref="AuthenticationBuilder"/> to add the handler to.</param>
  /// <param name="authenticationScheme">The authentication scheme to use.</param>
  /// <returns>The <see cref="AuthenticationBuilder"/> so that additional schemes can be chained.</returns>
  public static AuthenticationBuilder AddMonoCloudAuthentication(this AuthenticationBuilder builder, string authenticationScheme) => builder.AddMonoCloudAuthentication(authenticationScheme, null);
  /// <summary>
  /// Adds the MonoCloud authentication handler to the specified <see cref="AuthenticationBuilder"/>
  /// using the default authentication scheme and an action to configure the options.
  /// </summary>
  /// <param name="builder">The <see cref="AuthenticationBuilder"/> to add the handler to.</param>
  /// <param name="configureOptions">An action to configure the <see cref="MonoCloudAuthenticationOptions"/>.</param>
  /// <returns>The <see cref="AuthenticationBuilder"/> so that additional schemes can be chained.</returns>
  public static AuthenticationBuilder AddMonoCloudAuthentication(this AuthenticationBuilder builder, Action<MonoCloudAuthenticationOptions> configureOptions) => builder.AddMonoCloudAuthentication(MonoCloudAuthenticationDefaults.AuthenticationScheme, configureOptions);
  /// <summary>
  /// Adds the MonoCloud authentication handler to the specified <see cref="AuthenticationBuilder"/>
  /// using a custom authentication scheme and an action to configure the options.
  /// </summary>
  /// <param name="builder">The <see cref="AuthenticationBuilder"/> to add the handler to.</param>
  /// <param name="authenticationScheme">The authentication scheme to use.</param>
  /// <param name="configureOptions">An action to configure the <see cref="MonoCloudAuthenticationOptions"/>.</param>
  /// <returns>The <see cref="AuthenticationBuilder"/> so that additional schemes can be chained.</returns>
  /// <remarks>
  /// The scheme is registered manually rather than through <see cref="AuthenticationBuilder.AddScheme{TOptions,THandler}(string,Action{TOptions})"/>:
  /// that overload requires the handler to derive from <c>AuthenticationHandler&lt;MonoCloudAuthenticationOptions&gt;</c>,
  /// which a <see cref="JwtBearerHandler"/> subclass cannot satisfy. The registrations below mirror what the
  /// framework does internally for any authentication scheme.
  /// </remarks>
  public static AuthenticationBuilder AddMonoCloudAuthentication(this AuthenticationBuilder builder, string authenticationScheme, Action<MonoCloudAuthenticationOptions>? configureOptions)
  {
    builder.Services.AddHttpClient(MonoCloudAuthenticationDefaults.HttpClientName);

    builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<MonoCloudAuthenticationOptions>, PostConfigureMonoCloudAuthenticationOptions>());
    builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<MonoCloudAuthenticationOptions>, PostConfigureMonoCloudAuthenticationTimeProvider>());

    builder.Services.Configure<AuthenticationOptions>(o => o.AddScheme(authenticationScheme, scheme =>
    {
      scheme.HandlerType = typeof(MonoCloudAuthenticationHandler);
      scheme.DisplayName = null;
    }));

    if (configureOptions is not null)
    {
      builder.Services.Configure(authenticationScheme, configureOptions);
    }

    builder.Services.AddOptions<MonoCloudAuthenticationOptions>(authenticationScheme).Validate(o =>
    {
      o.Validate(authenticationScheme);
      return true;
    });

    builder.Services.AddTransient<MonoCloudAuthenticationHandler>();

    return builder;
  }
}
