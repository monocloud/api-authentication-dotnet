// ReSharper disable ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract

namespace MonoCloud.Backend;

/// <summary>
/// Handles authentication for MonoCloud by providing authentication logic specific to the MonoCloud platform.
/// </summary>
/// <remarks>
/// This handler processes authentication tokens and performs token introspection to validate incoming requests.
/// </remarks>
public class MonoCloudAuthenticationHandler : AuthenticationHandler<MonoCloudAuthenticationOptions>
{
  private readonly IIntrospectionCache _cache;
  private OpenIdConnectConfiguration? _configuration;

  /// <summary>
  /// Initializes a new instance of the <see cref="MonoCloudAuthenticationHandler"/> class.
  /// </summary>
#if NET8_0_OR_GREATER
  public MonoCloudAuthenticationHandler(IOptionsMonitor<MonoCloudAuthenticationOptions> options,
    UrlEncoder encoder,
    ILoggerFactory logger,
#pragma warning disable CS0618 // Type or member is obsolete
    ISystemClock? clock = null,
#pragma warning restore CS0618 // Type or member is obsolete
    IIntrospectionCache? cache = null) : base(options, logger, encoder)
  {
    _cache = cache!;
  }
#else
  [Obsolete("ISystemClock is obsolete, use TimeProvider on AuthenticationSchemeOptions instead.")]
  public MonoCloudAuthenticationHandler(IOptionsMonitor<MonoCloudAuthenticationOptions> options,
    UrlEncoder encoder,
    ILoggerFactory logger,
    ISystemClock clock,
    IIntrospectionCache? cache = null) : base(options, logger, encoder, clock)
  {
    _cache = cache!;
  }
#endif

  private static readonly ConcurrentDictionary<string, Lazy<Task<IntrospectionResult>>> IntrospectionCache = new();

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
      Logger.LogWarning("Authentication failed for scheme {SchemeName}: Missing token", Scheme.Name);
      return AuthenticateResult.Fail("Missing Token");
    }

    if (!Options.IntrospectJwtTokens && new JsonWebTokenHandler().CanReadToken(token))
    {
      Logger.LogDebug("Token is a JWT. Handling with JWT bearer authentication");
      return await HandleJwtBearerAuthenticationAsync(token);
    }

    Logger.LogDebug("Handling with introspection");
    return await HandleOpaqueTokenAuthenticationAsync(token);
  }

  private async Task<AuthenticateResult> HandleJwtBearerAuthenticationAsync(string token)
  {
    Logger.LogDebug("Starting JWT token validation");

    try
    {
      if (_configuration is null && Options.ConfigurationManager is not null)
      {
        _configuration ??= await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
      }

      var validationParameters = Options.JwtTokenValidationParameters.Clone();

      if (_configuration != null)
      {
        var issuers = new[] { _configuration.Issuer };

        validationParameters.ValidIssuers = validationParameters.ValidIssuers?.Concat(issuers) ?? issuers;

        validationParameters.IssuerSigningKeys = validationParameters.IssuerSigningKeys?.Concat(_configuration.SigningKeys) ?? _configuration.SigningKeys;
      }

      if (Options.ClockSkew.HasValue)
      {
        validationParameters.ClockSkew = Options.ClockSkew.Value;
      }

      var tokenValidationResult = await Options.JwtTokenHandler.ValidateTokenAsync(token, validationParameters);

      if (tokenValidationResult.IsValid)
      {
        var claims = tokenValidationResult.ClaimsIdentity.Claims.ToList();

        var authenticationType = Options.AuthenticationType ?? Options.JwtTokenValidationParameters.AuthenticationType ?? Scheme.Name;
        var roleClaimType = Options.RoleClaimType ?? Options.JwtTokenValidationParameters.RoleClaimType;
        var nameClaimType = Options.NameClaimType ?? Options.JwtTokenValidationParameters.NameClaimType;

        claims.NormalizeGroupClaims(roleClaimType);

        var identity = new ClaimsIdentity(claims, authenticationType, nameClaimType, roleClaimType);

        var principal = new ClaimsPrincipal(identity);

        Logger.LogInformation("JWT token successfully validated for user: {NameClaim}", principal.Identity?.Name);

        if (Options.ValidateCertificateBinding(Context))
        {
          var certificateBindingResult = await ValidateCertificateBinding(identity.Claims);
          if (certificateBindingResult is not null)
          {
            return certificateBindingResult;
          }
        }

        var validatedToken = tokenValidationResult.SecurityToken;

        var tokenValidatedContext = new TokenValidatedContext(Context, Scheme, Options)
        {
          Principal = principal,
          Token = validatedToken,
          Properties =
              {
                ExpiresUtc = GetSafeDateTime(validatedToken.ValidTo),
                IssuedUtc = GetSafeDateTime(validatedToken.ValidFrom)
              }
        };

        await Events.TokenValidated(tokenValidatedContext);

        if (tokenValidatedContext.Result is not null)
        {
          return tokenValidatedContext.Result;
        }

        if (Options.SaveToken)
        {
          tokenValidatedContext.Properties.StoreTokens(new List<AuthenticationToken> { new() { Name = "access_token", Value = token } });
        }

        tokenValidatedContext.Success();

        return tokenValidatedContext.Result!;
      }

      Logger.LogWarning(tokenValidationResult.Exception, "JWT validation failed for token. Message: {ErrorMessage}", tokenValidationResult.Exception?.Message ?? "Validation failed with no exception");

      if (Options.ConfigurationManager is not null && Options is { RefreshOnIssuerKeyNotFound: true } && tokenValidationResult.Exception is SecurityTokenSignatureKeyNotFoundException)
      {
        Options.ConfigurationManager.RequestRefresh();
      }

      tokenValidationResult.Exception ??= new SecurityTokenValidationException("Unable to validate the Token");

      return await AuthenticationFailed(tokenValidationResult.Exception.Message, Context, Scheme, Events, Options);
    }
    catch (Exception e)
    {
      Logger.LogError(e, "An unhandled exception occurred during JWT token authentication for scheme {SchemeName}", Scheme.Name);

      if (Options.ConfigurationManager is not null && Options is { RefreshOnIssuerKeyNotFound: true } && e is SecurityTokenSignatureKeyNotFoundException)
      {
        Options.ConfigurationManager.RequestRefresh();
      }

      return await AuthenticationFailed(e.Message, Context, Scheme, Events, Options);
    }
  }

  private async Task<AuthenticateResult> HandleOpaqueTokenAuthenticationAsync(string token)
  {
    if (string.IsNullOrEmpty(Options.ClientId))
    {
      throw new ArgumentNullException(nameof(Options.ClientId), "Client ID must be set");
    }

    if (string.IsNullOrEmpty(Options.TenantDomain))
    {
      throw new ArgumentNullException(nameof(Options.TenantDomain), "Tenant Domain must be set");
    }

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
        else
        {
          Logger.LogDebug("Proceeding to introspection");
        }
      }

      Logger.LogDebug("Starting token introspection process");

      var introspectionResult = await IntrospectionCache.GetOrAdd(token, _ => new Lazy<Task<IntrospectionResult>>(async () => await IntrospectTokenAsync(token))).Value;

      var introspectionClaims = introspectionResult.Claims.ToList();

      if (introspectionResult.IsActive)
      {
        Logger.LogInformation("Introspection successful. Token is active");

        if (Options.EnableCaching)
        {
          Logger.LogDebug("Caching new claims for active token");

          await _cache.SetClaimsAsync(Options, token, introspectionClaims, Options.CacheDuration, Logger, Context.RequestAborted).ConfigureAwait(false);
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
      else
      {
        Logger.LogInformation("Introspection successful. Token is inactive");

        if (introspectionClaims.All(x => x.Type != "active"))
        {
          introspectionClaims.Add(new Claim("active", "false", ClaimValueTypes.Boolean));
        }

        if (Options.EnableCaching)
        {
          Logger.LogDebug("Caching inactive token claims");

          await _cache.SetClaimsAsync(Options, token, introspectionClaims, Options.CacheDuration, Logger, Context.RequestAborted).ConfigureAwait(false);
        }

        return await AuthenticationFailed("Token inactive", Context, Scheme, Events, Options);
      }
    }
    catch (Exception e)
    {
      Logger.LogError(e, "An unhandled exception occurred during opaque token introspection for scheme {SchemeName}", Scheme.Name);
      return await AuthenticationFailed("Introspection failed", Context, Scheme, Events, Options);
    }
    finally
    {
      IntrospectionCache.TryRemove(token, out _);
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

  private static async Task<AuthenticateResult> CreateOpaqueTokenTicket(
      IList<Claim> claims,
      string token,
      HttpContext httpContext,
      AuthenticationScheme scheme,
      MonoCloudAuthenticationEvents events,
      MonoCloudAuthenticationOptions options,
      ILogger logger)
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
      Principal = principal,
      Token = token
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

  private static DateTime? GetSafeDateTime(DateTime dateTime)
  {
    // Assigning DateTime.MinValue or default(DateTime) to a DateTimeOffset when in a UTC+X timezone will throw
    // Since we don't really care about DateTime.MinValue in this case let's just set the field to null
    if (dateTime == DateTime.MinValue)
    {
      return null;
    }

    return dateTime;
  }
}
