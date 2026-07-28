namespace MonoCloud.Authentication.Api.Shared.ClientAuth;

/// <summary>
/// Represents a mechanism for authenticating clients using JSON Web Token (JWT) assertions.
/// </summary>
/// <remarks>
/// This class enables clients to authenticate against a server by generating and using JWT assertions.
/// It supports various security key types for signing the JWT, such as symmetric keys, JSON web keys (JWKs),
/// and X.509 certificates.
/// JWT assertions are used to securely prove the identity of the client and allow the client to use
/// the server's resources.
/// </remarks>
/// <example>
/// The JwtAssertionAuth class can be instantiated with one of the following:
/// <list type="number">
/// <item>
/// <description>A client secret (symmetric key) for client_secret_jwt.</description>
/// </item>
/// <item>
/// <description>A JSON web key (JWK) for private_key_jwt or client_secret_jwt (if an 'oct' key is passed in).</description>
/// </item>
/// <item>
/// <description>An X.509 certificate for private_key_jwt.</description>
/// </item>
/// </list>
/// </example>
public class JwtAssertionAuth : IMonoCloudClientAuth
{
  private SecurityKey SecurityKey { get; }

  private readonly string _defaultJwtAssertionSigningAlgorithm = SecurityAlgorithms.RsaSha256;

  /// <summary>
  /// Jwt assertion with shared secret 'client_secret_jwt'
  /// </summary>
  /// <param name="clientSecret"></param>
  public JwtAssertionAuth(string clientSecret)
  {
    SecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(clientSecret));
    _defaultJwtAssertionSigningAlgorithm = SecurityAlgorithms.HmacSha256;
  }

  /// <summary>
  /// Jwt assertion using a JWK. Can be a shared secret (oct key).
  /// </summary>
  /// <param name="jwk"></param>
  public JwtAssertionAuth(JsonWebKey jwk)
  {
    if (jwk.Kty == JsonWebAlgorithmsKeyTypes.Octet)
    {
      _defaultJwtAssertionSigningAlgorithm = SecurityAlgorithms.HmacSha256;
    }

    SecurityKey = jwk;
  }

  /// <summary>
  /// Jwt assertion using an asymmetric key (private_key_jwt).
  /// </summary>
  /// <param name="certificate"></param>
  public JwtAssertionAuth(X509Certificate2 certificate)
  {
    SecurityKey = new X509SecurityKey(certificate);
  }

  /// <inheritdoc />
  public async Task AuthenticateAsync(ClientAuthenticationContext context, CancellationToken cancellationToken)
  {
    JwtAssertion assertion;

    var jwtAssertionContext = new JwtAssertionContext(context.HttpContext, context.Scheme, context.Options);

    await context.Options.Events.CreatingJwtAssertion(jwtAssertionContext);

    var now = DateTime.UtcNow;

    if (jwtAssertionContext.JwtAssertion is not null)
    {
      assertion = jwtAssertionContext.JwtAssertion;
    }
    else
    {
      ArgumentNullException.ThrowIfNull(context.Options.ConfigurationManager);
      if (string.IsNullOrEmpty(context.Options.ClientId))
      {
        throw new ArgumentNullException(nameof(context.Options.ClientId), "ClientId must be set");
      }

      var config = await context.Options.ConfigurationManager.GetConfigurationAsync(cancellationToken);

      var tokenHandler = new JsonWebTokenHandler();


      IList<Claim> claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Iss, context.Options.ClientId),
                new(JwtRegisteredClaimNames.Sub, context.Options.ClientId),
                new(JwtRegisteredClaimNames.Aud, config.Issuer),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new(JwtRegisteredClaimNames.Nbf, now.ToUnixTimeStamp().ToString()),
                new(JwtRegisteredClaimNames.Iat, now.ToUnixTimeStamp().ToString()),
                new(JwtRegisteredClaimNames.Exp,
                    now.Add(context.Options.JwtAssertionDuration).ToUnixTimeStamp().ToString())
            };

      var tokenDescriptor = new SecurityTokenDescriptor
      {
        Subject = new ClaimsIdentity(claims),
        SigningCredentials = new SigningCredentials(SecurityKey,
              context.Options.JwtAssertionSigningAlgorithm ?? _defaultJwtAssertionSigningAlgorithm)
      };

      assertion = new JwtAssertion
      {
        Assertion = tokenHandler.CreateToken(tokenDescriptor),
        AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        AssertionCacheExpiry = DateTime.MaxValue,
      };
    }

    context.IntrospectionRequestPayload.Add("client_assertion_type", assertion.AssertionType);
    context.IntrospectionRequestPayload.Add("client_assertion", assertion.Assertion);
  }
}
