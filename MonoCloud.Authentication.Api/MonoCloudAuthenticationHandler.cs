// ReSharper disable ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract

namespace MonoCloud.Authentication.Api;

/// <summary>
/// Handles authentication for MonoCloud by providing authentication logic specific to the MonoCloud platform.
/// </summary>
/// <remarks>
/// <para>
/// This handler extends <see cref="JwtBearerHandler"/>. JWT access tokens are validated by the base handler
/// (signing keys, issuer, audience, lifetime) while opaque access tokens are validated through RFC 7662
/// introspection by this handler. Certificate binding (RFC 8705) and group and scope claim normalization are
/// applied on both paths.
/// </para>
/// <para>
/// Because <see cref="IOptionsMonitor{TOptions}"/> is covariant, the base handler's <c>Options</c> holds the
/// <see cref="MonoCloudAuthenticationOptions"/> instance produced by this scheme's options pipeline.
/// </para>
/// </remarks>
public class MonoCloudAuthenticationHandler : JwtBearerHandler
{
  private readonly IIntrospectionCache _cache;
  private OpenIdConnectConfiguration? _configuration;

  /// <summary>
  /// Initializes a new instance of the <see cref="MonoCloudAuthenticationHandler"/> class.
  /// </summary>
  public MonoCloudAuthenticationHandler(IOptionsMonitor<MonoCloudAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, IIntrospectionCache? cache = null) : base(options, logger, encoder)
  {
    _cache = cache!;
  }

  private static readonly ConcurrentDictionary<string, Lazy<Task<IntrospectionResult>>> IntrospectionCache = new();

  private static readonly JsonWebTokenHandler TokenReader = new();

  /// <summary>
  /// <see cref="MonoCloudAuthenticationOptions"/>
  /// </summary>
  protected new MonoCloudAuthenticationOptions Options => (MonoCloudAuthenticationOptions)base.Options;

  /// <summary>
  /// <see cref="MonoCloudAuthenticationEvents"/>
  /// </summary>
  protected new MonoCloudAuthenticationEvents Events
  {
    get => (MonoCloudAuthenticationEvents)base.Events!;
    set => base.Events = value;
  }

  /// <inheritdoc />
  protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new MonoCloudAuthenticationEvents());

  /// <inheritdoc />
  protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
  {
    Logger.LogDebug("Starting authentication process for scheme: {SchemeName}", Scheme.Name);

    var messageReceivedContext = new MessageReceivedContext(Context, Scheme, Options);

    await Events.MessageReceived(messageReceivedContext);

    if (messageReceivedContext.Result != null)
    {
      return messageReceivedContext.Result;
    }

    var token = messageReceivedContext.Token;

    if (string.IsNullOrEmpty(token))
    {
      Logger.LogDebug("Token not found in message context. Trying to get it from Authorization header");

      var authorization = Context.Request.Headers["Authorization"].FirstOrDefault();

      if (!string.IsNullOrEmpty(authorization))
      {
        token = authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? authorization[("Bearer".Length + 1)..].Trim() : null;
      }
    }

    if (string.IsNullOrEmpty(token))
    {
      Logger.LogDebug("Authentication skipped for scheme {SchemeName}: no bearer token present", Scheme.Name);
      return AuthenticateResult.NoResult();
    }

    if (!Options.IntrospectJwtTokens && TokenReader.CanReadToken(token))
    {
      Logger.LogDebug("Token is a JWT. Handling with JWT bearer authentication");
      return await HandleJwtBearerAuthenticationAsync(token);
    }

    Logger.LogDebug("Handling with introspection");
    return await HandleOpaqueTokenAuthenticationAsync(token!);
  }

  private async Task<AuthenticateResult> HandleJwtBearerAuthenticationAsync(string token)
  {
    // The base handler always raises MessageReceived and re-reads the Authorization header itself. Swapping
    // in an interceptor for the duration of the call keeps the consumer's MessageReceived to a single
    // invocation, guarantees the base handler validates exactly the token routed here, and lets group and
    // scope normalization and certificate binding run before the consumer's TokenValidated hook.
    var events = Events;

    Events = new InterceptingEvents(events, token, this);

    try
    {
      return await base.HandleAuthenticateAsync();
    }
    finally
    {
      Events = events;
    }
  }

  private async Task<AuthenticateResult> HandleOpaqueTokenAuthenticationAsync(string token)
  {
    if (string.IsNullOrEmpty(Options.ClientId))
    {
      throw new ArgumentNullException(nameof(Options.ClientId), "Client ID must be set");
    }

    if (string.IsNullOrEmpty(Options.Authority))
    {
      throw new ArgumentNullException(nameof(Options.Authority), "Authority must be set");
    }

    var cacheKey = $"{Scheme.Name}|{token}";

    try
    {
      if (Options.EnableCaching)
      {
        Logger.LogDebug("Attempting to retrieve claims from cache");

        IList<Claim>? claims = null;
        try
        {
          claims = await _cache.GetClaimsAsync(Options, token, Context.RequestAborted).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
          Logger.LogError(ex, "An error occurred while accessing the distributed cache");
        }

        if (claims is not null)
        {
          Logger.LogInformation("Claims successfully retrieved from cache");

          // find out if it is a cached inactive token
          var isInActive = claims.FirstOrDefault(c =>
              string.Equals(c.Type, "active", StringComparison.OrdinalIgnoreCase) &&
              string.Equals(c.Value, "false", StringComparison.OrdinalIgnoreCase));

          if (isInActive != null)
          {
            Logger.LogInformation("Cached token is inactive");
            return await AuthenticationFailed("Token inactive", Context, Scheme, Events, Options);
          }

          if (Options.ValidateCertificateBinding(Context))
          {
            var certificateBindingResult = await ValidateCertificateBinding(claims);
            if (certificateBindingResult is not null)
            {
              return certificateBindingResult;
            }
          }

          return await CreateOpaqueTokenTicket(claims, token, Context, Scheme, Events, Options, Logger);
        }

        Logger.LogDebug("Proceeding to introspection");
      }

      Logger.LogDebug("Starting token introspection process");

      var introspectionResult = await IntrospectionCache.GetOrAdd(cacheKey, _ => new Lazy<Task<IntrospectionResult>>(async () => await IntrospectTokenAsync(token))).Value;

      var introspectionClaims = introspectionResult.Claims.ToList();

      if (introspectionResult.IsActive)
      {
        Logger.LogInformation("Introspection successful. Token is active");

        if (Options.EnableCaching)
        {
          Logger.LogDebug("Caching new claims for active token");

          await TrySetClaimsCacheAsync(token, introspectionClaims);
        }

        if (Options.ValidateCertificateBinding(Context))
        {
          var certificateBindingResult = await ValidateCertificateBinding(introspectionClaims);
          if (certificateBindingResult is not null)
          {
            return certificateBindingResult;
          }
        }

        return await CreateOpaqueTokenTicket(introspectionClaims, token, Context, Scheme, Events, Options, Logger);
      }

      Logger.LogInformation("Introspection successful. Token is inactive");

      if (introspectionClaims.All(x => x.Type != "active"))
      {
        introspectionClaims.Add(new Claim("active", "false", ClaimValueTypes.Boolean));
      }

      if (Options.EnableCaching)
      {
        Logger.LogDebug("Caching inactive token claims");

        await TrySetClaimsCacheAsync(token, introspectionClaims);
      }

      return await AuthenticationFailed("Token inactive", Context, Scheme, Events, Options);
    }
    catch (Exception e)
    {
      Logger.LogError(e, "An unhandled exception occurred during opaque token introspection for scheme {SchemeName}", Scheme.Name);

      var authenticationFailedContext = new AuthenticationFailedContext(Context, Scheme, Options)
      {
        Exception = e
      };

      await Events.AuthenticationFailed(authenticationFailedContext);

      if (authenticationFailedContext.Result != null)
      {
        return authenticationFailedContext.Result;
      }

      throw;
    }
    finally
    {
      IntrospectionCache.TryRemove(cacheKey, out _);
    }
  }

  private async Task TrySetClaimsCacheAsync(string token, IList<Claim> claims)
  {
    try
    {
      await _cache.SetClaimsAsync(Options, token, claims, Options.CacheDuration, Logger, Context.RequestAborted).ConfigureAwait(false);
    }
    catch (Exception ex)
    {
      Logger.LogError(ex, "An error occurred while writing to the distributed cache");
    }
  }

  private async Task<IntrospectionResult> IntrospectTokenAsync(string token)
  {
    ArgumentNullException.ThrowIfNull(Options.ConfigurationManager);

    _configuration ??= await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);

    ArgumentNullException.ThrowIfNull(_configuration);

    var introspectionEndpoint = _configuration.IntrospectionEndpoint;

    if (Options.ClientAuth is TlsAuth auth)
    {
      var mtlsEndpointAliases = new MtlsEndpointAliases();

      if (auth.TrustStore is not null)
      {
        if (_configuration.AdditionalData.TryGetValue("mtls_additional_endpoint_aliases", out var meae) && meae is JsonElement mtlsAdditionalEndpointAliasesElement)
        {
          var aliases = mtlsAdditionalEndpointAliasesElement.Deserialize<Dictionary<string, object>>();
          if (aliases is not null && aliases.TryGetValue(auth.TrustStore, out var mae) && mae is JsonElement mtlsEndpointAliasesElement)
          {
            mtlsEndpointAliases = mtlsEndpointAliasesElement.Deserialize<MtlsEndpointAliases>();
          }
        }
      }
      else
      {
        if (_configuration.AdditionalData.TryGetValue("mtls_endpoint_aliases", out var mae) && mae is JsonElement mtlsEndpointAliasesElement)
        {
          mtlsEndpointAliases = mtlsEndpointAliasesElement.Deserialize<MtlsEndpointAliases>();
        }
      }

      if (string.IsNullOrEmpty(mtlsEndpointAliases?.IntrospectionEndpoint))
      {
        throw new InvalidOperationException("The mTLS introspection endpoint alias was not found in the OpenID configuration. Ensure the discovery document contains an 'introspection_endpoint' under 'mtls_endpoint_aliases' (or, when a trust store is configured, under the matching entry in 'mtls_additional_endpoint_aliases').");
      }

      introspectionEndpoint = mtlsEndpointAliases.IntrospectionEndpoint;
    }

    using var request = new HttpRequestMessage(HttpMethod.Post, introspectionEndpoint);

    request.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

    var payload = new Dictionary<string, string>
        {
            { "token", token },
        };

    if (Options.ClientAuth is null)
    {
      throw new ArgumentNullException(nameof(Options.ClientAuth));
    }

    var authContext = new ClientAuthenticationContext(Options, request, payload, Context, Scheme);

    await Options.ClientAuth.AuthenticateAsync(authContext, Context.RequestAborted);

    request.Content = new FormUrlEncodedContent(payload);

    var introspectionContext = new IntrospectionRequestContext(Context, Scheme, Options) { IntrospectionRequest = request };

    await Events.Introspection(introspectionContext);

    using var response = await Options.HttpClient.SendAsync(introspectionContext.IntrospectionRequest).ConfigureAwait(false);

    response.EnsureSuccessStatusCode();

    var content = await response.Content.ReadAsStringAsync();

    return new IntrospectionResult(JsonDocument.Parse(content).RootElement);
  }

  private static async Task<AuthenticateResult> AuthenticationFailed(
      string error,
      HttpContext httpContext,
      AuthenticationScheme scheme,
      MonoCloudAuthenticationEvents events,
      MonoCloudAuthenticationOptions options)
  {
    var authenticationFailedContext = new AuthenticationFailedContext(httpContext, scheme, options)
    {
      Exception = new Exception(error)
    };

    await events.AuthenticationFailed(authenticationFailedContext);

    // ReSharper disable once NullCoalescingConditionIsAlwaysNotNullAccordingToAPIContract
    return authenticationFailedContext.Result ?? AuthenticateResult.Fail(error);
  }

  private static async Task<AuthenticateResult> CreateOpaqueTokenTicket(IList<Claim> claims, string token, HttpContext httpContext, AuthenticationScheme scheme, MonoCloudAuthenticationEvents events, MonoCloudAuthenticationOptions options, ILogger logger)
  {
    var authenticationType = options.AuthenticationType ?? scheme.Name;

    logger.LogInformation("Creating authentication ticket for user with authentication type '{AuthType}'", authenticationType);

    if (options.RoleClaimType is not null)
    {
      claims.NormalizeGroupClaims(options.RoleClaimType);
    }

    var id = new ClaimsIdentity(claims, authenticationType, options.NameClaimType, options.RoleClaimType);
    var principal = new ClaimsPrincipal(id);

    var tokenValidatedContext = new TokenValidatedContext(httpContext, scheme, options)
    {
      Principal = principal
    };

    await events.TokenValidated(tokenValidatedContext);

    if (tokenValidatedContext.Result is not null)
    {
      return tokenValidatedContext.Result;
    }

    if (options.SaveToken)
    {
      tokenValidatedContext.Properties.StoreTokens(new List<AuthenticationToken> { new() { Name = "access_token", Value = token } });
    }

    tokenValidatedContext.Success();

    return tokenValidatedContext.Result!;
  }

  private async Task<AuthenticateResult?> ValidateCertificateBinding(IEnumerable<Claim> claims)
  {
    Logger.LogDebug("Starting certificate binding validation");

    var clientCertificate = await Options.CertificateRetriever(Context);

    if (clientCertificate is null)
    {
      return await AuthenticationFailed("Client certificate is not present", Context, Scheme, Events, Options);
    }

    // Base64url encoding: regular base64, but `-` for `+` and `_` for `/`, omit trailing `=`
    var clientCertHash = Convert.ToBase64String(SHA256.HashData(clientCertificate.RawData))
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    var cnfClaim = claims.FirstOrDefault(x => x.Type == "cnf");
    if (cnfClaim is null)
    {
      return await AuthenticationFailed("Access token does not contain a 'cnf' (confirmation) claim for certificate binding", Context, Scheme, Events, Options);
    }

    Dictionary<string, JsonElement>? cnfClaimValue;
    try
    {
      cnfClaimValue = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(cnfClaim.Value);
    }
    catch (Exception)
    {
      return await AuthenticationFailed("Malformed 'cnf' claim for certificate binding", Context, Scheme, Events, Options);
    }

    if (cnfClaimValue == null)
    {
      return await AuthenticationFailed("The 'cnf' claim could not be parsed", Context, Scheme, Events, Options);
    }

    string? certHash = null;
    if (cnfClaimValue.TryGetValue("x5t#S256", out var x5tElement) && x5tElement.ValueKind is JsonValueKind.String)
    {
      certHash = x5tElement.GetString();
    }

    if (certHash is null)
    {
      return await AuthenticationFailed("The 'cnf' claim does not contain an 'x5t#S256' member specifying the certificate hash for binding", Context, Scheme, Events, Options);
    }

    if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(certHash), Encoding.UTF8.GetBytes(clientCertHash)))
    {
      return await AuthenticationFailed("The certificate hash in the access token does not match the presented client certificate (certificate binding validation failed)", Context, Scheme, Events, Options);
    }

    var context = new CertificateBindingValidatedContext(Context, Scheme, Options);

    await Events.CertificateBindingValidated(context);

    return context.Result;
  }

  private void NormalizeGroups(TokenValidatedContext context)
  {
    if (context.Principal?.Identity is not ClaimsIdentity identity)
    {
      return;
    }

    var roleClaimType = Options.RoleClaimType ?? Options.TokenValidationParameters.RoleClaimType;

    if (string.IsNullOrEmpty(roleClaimType) || !identity.Claims.HasNormalizableGroupClaims(roleClaimType))
    {
      return;
    }

    var claims = identity.Claims.ToList();

    claims.NormalizeGroupClaims(roleClaimType);

    ReplaceClaims(identity, claims);
  }

  private static void NormalizeScopes(TokenValidatedContext context)
  {
    if (context.Principal?.Identity is not ClaimsIdentity identity || !identity.Claims.HasNormalizableScopeClaims())
    {
      return;
    }

    var claims = identity.Claims.ToList();

    claims.NormalizeScopeClaims();

    ReplaceClaims(identity, claims);
  }

  private static void ReplaceClaims(ClaimsIdentity identity, IEnumerable<Claim> claims)
  {
    // Swap the claim set in place on the validated identity. Constructing a replacement ClaimsIdentity
    // here would silently downgrade Wilson 8's CaseSensitiveClaimsIdentity (ordinal claim-type matching)
    // to the case-insensitive base type and drop identity state such as Actor and Label.
    foreach (var claim in identity.Claims.ToList())
    {
      identity.RemoveClaim(claim);
    }

    identity.AddClaims(claims);
  }

  private static void Apply(AuthenticateResult result, TokenValidatedContext context)
  {
    if (result.Failure is not null)
    {
      context.Fail(result.Failure);
    }
    else if (result.Succeeded)
    {
      context.Principal = result.Principal;
      context.Properties = result.Properties!;
      context.Success();
    }
    else
    {
      context.NoResult();
    }
  }

  private sealed class InterceptingEvents(MonoCloudAuthenticationEvents inner, string token, MonoCloudAuthenticationHandler handler) : MonoCloudAuthenticationEvents
  {
    public override Task MessageReceived(MessageReceivedContext context)
    {
      context.Token = token;
      return Task.CompletedTask;
    }

    public override async Task TokenValidated(TokenValidatedContext context)
    {
      handler.NormalizeGroups(context);

      NormalizeScopes(context);

      if (handler.Options.ValidateCertificateBinding(context.HttpContext))
      {
        var result = await handler.ValidateCertificateBinding(context.Principal!.Claims);

        if (result is not null)
        {
          Apply(result, context);
          return;
        }
      }

      await inner.TokenValidated(context);
    }

    public override Task AuthenticationFailed(AuthenticationFailedContext context) => inner.AuthenticationFailed(context);

    public override Task Challenge(JwtBearerChallengeContext context) => inner.Challenge(context);

    public override Task Forbidden(ForbiddenContext context) => inner.Forbidden(context);

    public override Task CertificateBindingValidated(CertificateBindingValidatedContext context) => inner.CertificateBindingValidated(context);

    public override Task Introspection(IntrospectionRequestContext context) => inner.Introspection(context);

    public override Task CreatingJwtAssertion(JwtAssertionContext context) => inner.CreatingJwtAssertion(context);
  }
}
