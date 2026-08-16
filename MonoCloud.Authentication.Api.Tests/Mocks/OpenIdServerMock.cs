namespace MonoCloud.Authentication.Api.Tests.Mocks;

public class OpenIdServerMock
{
  public const string ClientId = "client_id";
  public const string SymmetricSecret = "super-secret-test-client-secret-value-0123456789";
  public static readonly SecurityKey ClientSecretJwtJwk = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SymmetricSecret));
  public static readonly JsonWebKey PublicJwkKey = JsonWebKey.Create("""{"kty":"RSA","e":"AQAB","n":"tWfKW4UOMKnenBYKru6QRri5azoEZnUuCCRDzWg45HRggvXqAZLNMXorb_yzF-WD5Mdg1XyAh7nIAh9JKWv7_cwjceb5684KpCeARE6iuqgrIU9lDcKCI_KbaAttSIY-uA0mACBT3Yc3pQ838QKX_ch9FdqEIxMlwPyFGxVNqmB-jHTTqyK-qiG8kkdiL1re2LaY-6GRLHLFiqLmvzeNX_ha1Fj4xOe-tTmKxaClGDZfhjWmRSXMF2k_SpZA_7KBHW4SXc-5fCPkXQyA5F7iyKHg1rbdAo24mPR8eZgKYtEcOLxozy3Uth3EeppLd4x5Vc3TZpYxyUlLO3I-0-ZbJw"}""");
  public static readonly JsonWebKey PrivateJwkKey = JsonWebKey.Create("""{"p":"4pAKy78XQtrcwwMU6W67lMtb-ldEFxcEbPaWljEwUqBoyS5ySoa6PvLieSjZxR12huH5auM204o4UB8ckaZK8LPKIvu_3iYLq1VwfcZeki9jV-0k0tGSlMpxwGe3mWbJpGVuOkPbIIeONrWoVI_qHq9Y01Dk__L8G0Y24I_GPiU","kty":"RSA","q":"zPm46gpf4BIhupIqjgEZn2xZY31DrYtjNLQCWvVokjvy2uITTYLeTKW3Mx_Bpl4Sh4oNgSb6tRYVUze5Hg7gp_NlSYLmoJVbIkjmcNsRzuwGp9vuWt0Uba5Pv6pBOe2JoILh6kTPDFa5NYSpzYQdJ5KGIiWWN96uDNVUMbp39Fs","d":"lJ2qZ94S6QVRzbg1Gmlxo67UoScP0cywYJUtQwveiDNbmg7TnmRhXOaEzaNOKgarTnOVPnFYb1lhpXNyIdBIyv1CEJ-1Il1T1HZUHCH8KUV6yDheRq6SpdatQMkTx_XLTkffWP0jF_seOEjGgNmqIYzuBUhXNtEJ_hgjCDQkw64WlFL8cxR_a62DfhLNXAiq6Gq0xmzZaEKGKpaeMWHSFrj99mKm_e19pzbGNNBiCZzoM7YSdhgFaYAh_MlHfrIVokHi7He_nYWMK8NfRxxU-s8rvlvaWLdLgAelR1Nl7KZmDooUSVy01hvRgyBbYCAQ34SzKHFBVn92bD2c_E3auQ","e":"AQAB","qi":"HCRLITApmJnGcp0mS63xhLALC32-ovwIDmvfML0H--lQDcdYUR0407FNSYnJPgLgTq56veMFLK5KK1Cf0XDeCIrOw4GlBTMHGlFaMYbPpR6JMYst_8U3y9UXYYqWH_igfjNcDqzIga2508vlQIDQqBkO0_5NEA-o0prmiIH4CBI","dp":"zHZBx-4ECAmMAVHepWuRTY7YyuvGPzA-hjdjXte1TFwHNMf9zNQZcIWxbLY5EXKtbLyyYov7Bp1OhMAPAEKaju8yFLAtT0X2cgEBLADBiBvMA6W3_am0JyMr1P_E6WOhxgLjnyFtt8WdyjHWX7ohBuAnwUzX3URj0BllnPMjbSE","dq":"jvX5J5r2xaQ_zA2YCpTv1wZNzhsW8dqO5bpLDj-toJiZSFp3lg8ZlqHaBZk3ih6Ak_IQeyzBnT16wCDURwefXuRel4fp7MRe3Km1t67DW-u4tKirNMqPLfRugMJxXcKzw7SldqxpMDToVlBh0go7_1atoPFQNUVlZWQApfJlKZM","n":"tWfKW4UOMKnenBYKru6QRri5azoEZnUuCCRDzWg45HRggvXqAZLNMXorb_yzF-WD5Mdg1XyAh7nIAh9JKWv7_cwjceb5684KpCeARE6iuqgrIU9lDcKCI_KbaAttSIY-uA0mACBT3Yc3pQ838QKX_ch9FdqEIxMlwPyFGxVNqmB-jHTTqyK-qiG8kkdiL1re2LaY-6GRLHLFiqLmvzeNX_ha1Fj4xOe-tTmKxaClGDZfhjWmRSXMF2k_SpZA_7KBHW4SXc-5fCPkXQyA5F7iyKHg1rbdAo24mPR8eZgKYtEcOLxozy3Uth3EeppLd4x5Vc3TZpYxyUlLO3I-0-ZbJw"}""");
  private static string CertsDir => Path.Combine(Directory.GetParent(TestContext.CurrentContext.TestDirectory)!.Parent!.Parent!.FullName, "Certs");
  public static readonly X509Certificate2 PrivateKeyCert = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine(CertsDir, "private_key_jwt_cert.pfx"), "password");
  public static readonly X509Certificate2 MtlsClientCert = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine(CertsDir, "mtls_client_cert.pfx"), "password");

  public const string MtlsThumbprint = "8Coyzj9l6bodEROsdwvUKBQTpY9fPoYuHnNdqwHUULA";

  public const string SpiffeJwtSvid = "test-spiffe-jwt-svid";

  public const string Issuer = "https://localhost";
  public const string DiscoveryEndpoint = "https://localhost/.well-known/openid-configuration";
  public const string TokenEndpoint = "https://localhost/token";
  public const string JwksEndpoint = "https://localhost/jwks";
  public const string IntrospectionEndpoint = "https://localhost/introspect";
  public const string MtlsIntrospectionEndpoint = "https://localhost/mtls/introspect";
  public const string CustomTrustStoreMtlsIntrospectionEndpoint = "https://localhost/mtls/id/introspect";

  private static readonly JsonWebKey JwksPrivateKey = new("""{"p": "_jjHcC2m6yFBmZnnwgnYKeHrEHtbiaLVFmDXGvRvFp4uK8eX92q6ZpHGW_qq1M45H5-ts1ELjYinsTZBKbGNfw03OA2LshYDAkarZOAaK9KoSoHHawAvV4JIWA9iVHvkgL8lU5AODsb4P5uNiCjk6ELjycmao286oPR02ZbdMZE","kty": "RSA","q": "x6sqnHACAd95rIX3KmeZkQJL6sPJRXX2zi8VxCMDEgCT-2pw7ezPQh4NS8Uf3O91hltilOMf2TF1t1OCqRaa5KGG4iFmfIzSsGuRKll8eod4_Cxlv32IUlu-m8kkRVaJ4CoX0ZaS3j_-xF7SUFMuuQv7JuLxJtB9pxixlRkrLsU","d": "PeCbYhfRAoTSJ2vckrw3YIN0Y7-ddxt9Z1VrGxKxTfWm7Xxu0YUvD0pH-XAEaLkp684nwP0ukfYTON-AipvlAMo00ZddbpeVSXaR8eUYaYR_2hhIhbEqQ0TYNgAqENywlQKrKZleOIXbaqhzp36h5pOz2BuXRSGvj44k5gPpGq_tdKcKDGkGxPttD1su0zHOcpd3Kf_nvRGPxg9pUJrcwgh_lKHAW_LnYYYawYmlwty8M4jRp9jrJu9jmgYFbfxUbfDjiGQui-D4dhJ0amTSpnQlrbSwLd1Mo2-0UnTcsB71t7iXHmAJpWD0SYkokQFXkTrZkjulLcSRwUilsEABAQ","e": "AQAB","use": "sig","kid": "test","qi": "9p2BxPZN342F_Le35CvUXhXHBx0dvFmplMIl71TPs7_cUzgjqGVLLmSjP4gpqG7nRJI6uhi669OezmxYgvXXlmAzaZ2plD3NawldRBB6AyKwxncvklVNpt7a5j-XZTpvPAR9BpqmfFm2Edg5lE-8t9NVFIjrQPMqkJwPZMGYqNw","dp": "vxAfXEEDTX4-FlokY6IQc1HW4BlGL8hQjDQWFq0U_JO_samdnhb5pvLyeNiJIc0oA4t3-ef0XdgR6E8VZGeMJ6vgD2Gm1x5R_pjsYbFIGh2F3BFztgh6jDNfecd-KG7Ayr5eKFKBLjv-AZhAI9BQUftLxbGeZizHjIaNd6c58PE","alg": "RS256","dq": "vM6q2ItCGqtLz0xO0RZuLKVTTIgfB0PpQkdb-cBx4tARHykj6JiJ1Ce-wuuAmdcF9yrrKYcsUqFmgxjA8Uui5JepiKO02goAITtWZgmAoA0C5tLE1DLMebSvpXiqh7axYfvr0hDkiK1TKDXSAormH62orLjk-KMmbp_3LNpD71E","n": "xkgdRhX4BK3laqvI6Do0uzD6brOPh79eNs9qAEXZp93QeWhyVKpwtcPonVCiIYP2pjpso0jxuEKOSAhUPdcKBbKqFHr0tYLG_DFo_9Z42Q7jMWtUVwpDcphzsZj1v7JP1JTOPD0ub-dqZuOXDkxSYLPGq1PBuVC4ETHftTU2NORidjOfaOBKjk1zBUmYwimaGgMh6veRn_9frQE90kDoizKG4_HTo5UdwJF34RekB1BoZl-BVxl22OOCyqyI4YOxxInzC76MXW8P3JS2CeOEmMz2ZM5CgX23MdiWC2j_7IMuEzmgNMmU7KlUhO6RKgnS6HYIHp4B8VWkAA_wU3oylQ"}""");
  private readonly DateTime? _now = DateTime.UtcNow;
  private const string JwksResponse = """{"keys": [{"kty": "RSA","e": "AQAB", "use": "sig", "kid": "test", "alg": "RS256", "n": "xkgdRhX4BK3laqvI6Do0uzD6brOPh79eNs9qAEXZp93QeWhyVKpwtcPonVCiIYP2pjpso0jxuEKOSAhUPdcKBbKqFHr0tYLG_DFo_9Z42Q7jMWtUVwpDcphzsZj1v7JP1JTOPD0ub-dqZuOXDkxSYLPGq1PBuVC4ETHftTU2NORidjOfaOBKjk1zBUmYwimaGgMh6veRn_9frQE90kDoizKG4_HTo5UdwJF34RekB1BoZl-BVxl22OOCyqyI4YOxxInzC76MXW8P3JS2CeOEmMz2ZM5CgX23MdiWC2j_7IMuEzmgNMmU7KlUhO6RKgnS6HYIHp4B8VWkAA_wU3oylQ" }]}""";
  private readonly Mock<HttpMessageHandler> _handlerMock = new();
  private object IntrospectionSuccessResponse => new
  {
    active = true,
    iss = Issuer,
    scope = "openid resource",
    aud = new[] { Issuer, TokenEndpoint },
    sub = "1234567890",
    client_id = ClientId,
    groups = new List<object>
        {
            new { id = "adminId", name = "admin" },
            new { id = "moderatorId", name = "moderator" }
        },
    groupsAlt = new List<object>
        {
            new { id = "editorId", name = "editor" },
            new { id = "viewerId", name = "viewer" }
        },
    iat = ToUnixTimeStamp(_now!.Value),
    exp = ToUnixTimeStamp(_now!.Value.AddMinutes(5)),
    nbf = ToUnixTimeStamp(_now!.Value),
    cnf = new Dictionary<string, object> { { "x5t#S256", MtlsThumbprint } }

  };

  public void SetupIntrospection(bool? failure = null, HttpStatusCode? status = null, string? authType = null, string? endpoint = null, object? body = null, Func<Task>? beforeRespond = null)
  {
    body ??= failure.HasValue && failure.Value ? new { active = false } : IntrospectionSuccessResponse;

    status ??= HttpStatusCode.OK;

    if (status is not HttpStatusCode.OK)
    {
      body = new { error = "unknown_error" };
    }

    var introspectionEndpoint = endpoint ?? IntrospectionEndpoint;

    var matcher = ItExpr.Is<HttpRequestMessage>(req =>
        req.RequestUri != null && req.RequestUri.GetLeftPart(UriPartial.Path) == introspectionEndpoint &&
        req.Method == HttpMethod.Post &&
        req.Content != null &&
        req.Content.Headers.ContentType != null &&
        req.Content.Headers.ContentType.MediaType == "application/x-www-form-urlencoded" &&
        CheckAuth(req, authType));

    var json = body as string ?? JsonSerializer.Serialize(body);

    _handlerMock.Protected()
        .Setup<Task<HttpResponseMessage>>("SendAsync", matcher, ItExpr.IsAny<CancellationToken>())
        .Returns(async () =>
        {
          if (beforeRespond is not null)
          {
            await beforeRespond();
          }

          return new HttpResponseMessage
          {
            StatusCode = status.Value,
            Content = new StringContent(json)
          };
        });
  }

  public void SetupDiscovery(HttpStatusCode? status = null, bool? includeBody = true, bool? includeMtls = true, bool? includeAdditionalMtls = true, bool? includeCustomMtls = true)
  {
    object body = new { };

    if (includeBody.HasValue && includeBody.Value)
    {
      body = new
      {
        issuer = Issuer,
        token_endpoint = TokenEndpoint,
        jwks_uri = JwksEndpoint,
        introspection_endpoint = IntrospectionEndpoint,
        mtls_endpoint_aliases = includeMtls.HasValue && includeMtls.Value
              ? new { introspection_endpoint = MtlsIntrospectionEndpoint }
              : (object?)new { },
        mtls_additional_endpoint_aliases = includeAdditionalMtls.HasValue && includeAdditionalMtls.Value
              ? new
              {
                id = includeCustomMtls.HasValue && includeCustomMtls.Value
                      ? new { introspection_endpoint = CustomTrustStoreMtlsIntrospectionEndpoint }
                      : (object?)new { },
              }
              : (object?)new { },
      };
    }

    status ??= HttpStatusCode.OK;

    var matcher = ItExpr.Is<HttpRequestMessage>(req => req.RequestUri != null && req.RequestUri.GetLeftPart(UriPartial.Path) == DiscoveryEndpoint && req.Method == HttpMethod.Get);

    Setup(matcher, status, body);
  }

  public void SetupJwks(HttpStatusCode? status = null)
  {
    status ??= HttpStatusCode.OK;

    var matcher = ItExpr.Is<HttpRequestMessage>(req => req.RequestUri != null && req.RequestUri.GetLeftPart(UriPartial.Path) == JwksEndpoint);

    Setup(matcher, status, JwksResponse);
  }

  public HttpClient Build()
  {
    _handlerMock.Protected()
        .Setup<Task<HttpResponseMessage>>("SendAsync", ItExpr.Is<HttpRequestMessage>(req => AllOtherRequests(req)), ItExpr.IsAny<CancellationToken>())
        .ReturnsAsync(new HttpResponseMessage
        {
          StatusCode = HttpStatusCode.InternalServerError,
          Content = new StringContent("[Test] Internal Server Error")
        });

    return new HttpClient(_handlerMock.Object);
  }

  public static string CreateAccessToken(IList<Claim>? payload = null, IEnumerable<string>? excludeClaims = null, SigningCredentials? signingCredentials = null)
  {
    var now = DateTime.UtcNow;

    var standardClaims = new List<Claim>
        {
            new("iss", Issuer),
            new("aud", $"[\"{Issuer}\",\"{TokenEndpoint}\"]", JsonClaimValueTypes.JsonArray),
            new("sub", "1234567890"),
            new("iat", ToUnixTimeStamp(now).ToString()),
            new("exp", ToUnixTimeStamp(now.AddMinutes(5)).ToString()),
            new("nbf", ToUnixTimeStamp(now).ToString()),
            new("client_id", ClientId),
            new("scope", "openid resource"),
            new("groups", "[{\"id\":\"adminId\",\"name\":\"admin\"},{\"id\":\"moderatorId\",\"name\":\"moderator\"}]", JsonClaimValueTypes.JsonArray),
            new("groupsAlt", "[{\"id\":\"editorId\",\"name\":\"editor\"},{\"id\":\"viewerId\",\"name\":\"viewer\"}]", JsonClaimValueTypes.JsonArray),
            new("cnf", $"{{\"x5t#S256\":\"{MtlsThumbprint}\"}}", JsonClaimValueTypes.Json)
        };

    if (payload is not null)
    {
      standardClaims = standardClaims.Where(x => payload.All(y => y.Type != x.Type)).ToList();
      standardClaims.AddRange(payload);
    }

    if (excludeClaims is not null)
    {
      var exclude = excludeClaims.ToHashSet();
      standardClaims = standardClaims.Where(x => !exclude.Contains(x.Type)).ToList();
    }

    var tokenHandler = new JsonWebTokenHandler();

    var tokenDescriptor = new SecurityTokenDescriptor
    {
      Subject = new ClaimsIdentity(standardClaims),
      SigningCredentials = signingCredentials ?? new SigningCredentials(JwksPrivateKey, SecurityAlgorithms.RsaSha256)
    };

    return tokenHandler.CreateToken(tokenDescriptor);
  }

  static bool AllOtherRequests(HttpRequestMessage request)
  {
    var uri = request.RequestUri?.GetLeftPart(UriPartial.Path);

    return uri != DiscoveryEndpoint && uri != IntrospectionEndpoint && uri != JwksEndpoint &&
           uri != MtlsIntrospectionEndpoint && uri != CustomTrustStoreMtlsIntrospectionEndpoint;
  }

  private void Setup(Expression matcher, HttpStatusCode? status = null, object? body = null)
  {
    _handlerMock.Protected()
       .Setup<Task<HttpResponseMessage>>("SendAsync", matcher, ItExpr.IsAny<CancellationToken>())
       .ReturnsAsync(new HttpResponseMessage
       {
         StatusCode = status ?? HttpStatusCode.OK,
         // String bodies (e.g. the raw JWKS document) are used verbatim; objects are JSON-serialized.
         Content = body is null ? null : new StringContent(body as string ?? JsonSerializer.Serialize(body))
       });
  }

  public void VerifyDiscoveryCalled(Times? times = null) => VerifyEndpointCalled(DiscoveryEndpoint, HttpMethod.Get, times);

  public void VerifyJwksCalled(Times? times = null) => VerifyEndpointCalled(JwksEndpoint, HttpMethod.Get, times);

  public void VerifyIntrospectionCalled(Times? times = null, string? endpoint = null) => VerifyEndpointCalled(endpoint ?? IntrospectionEndpoint, HttpMethod.Post, times);

  private void VerifyEndpointCalled(string endpoint, HttpMethod method, Times? times)
  {
    _handlerMock.Protected().Verify<Task<HttpResponseMessage>>("SendAsync", times ?? Times.Once(), ItExpr.Is<HttpRequestMessage>(req => req.RequestUri != null && req.RequestUri.GetLeftPart(UriPartial.Path) == endpoint && req.Method == method), ItExpr.IsAny<CancellationToken>());
  }

  private static bool CheckAuth(HttpRequestMessage request, string? authType)
  {
    switch (authType)
    {
      case "client_secret_basic":
      {
        if (request.Headers.Authorization is null || request.Headers.Authorization.Scheme != "Basic" ||
            request.Headers.Authorization?.Parameter is null)
        {
          return false;
        }

        var split = Encoding.UTF8.GetString(Convert.FromBase64String(request.Headers.Authorization.Parameter)).Split(":", 2);

        var clientId = split[0];
        var clientSecret = split[1];

        return clientId == ClientId && clientSecret == SymmetricSecret;
      }

      case "client_secret_post":
      {
        var requestBody = request.Content?.ReadAsStringAsync().GetAwaiter().GetResult();
        if (requestBody is null)
        {
          return false;
        }

        var body = ParseFormUrlEncodedString(requestBody);

        return body.TryGetValue("client_id", out var clientId) && clientId == ClientId && body.TryGetValue("client_secret", out var clientSecret) && clientSecret == SymmetricSecret;
      }

      case "client_secret_jwt" or "private_key_jwt":
      {
        var requestBody = request.Content?.ReadAsStringAsync().GetAwaiter().GetResult();
        if (requestBody is null)
        {
          return false;
        }

        var body = ParseFormUrlEncodedString(requestBody);

        // For assertion-based auth the client identity is carried by the assertion (iss/sub),
        // so a separate client_id parameter is optional; if present it must match.
        if (body.TryGetValue("client_id", out var clientId) && clientId != ClientId)
        {
          return false;
        }

        if (!body.TryGetValue("client_assertion", out var clientAssertion) || !body.TryGetValue("client_assertion_type", out var clientAssertionType) || clientAssertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
        {
          return false;
        }

        var securityKey = authType is "client_secret_jwt" ? ClientSecretJwtJwk : PublicJwkKey;

        var handler = new JsonWebTokenHandler();

        var validationParams = new TokenValidationParameters
        {
          ValidateIssuer = true,
          ValidIssuer = ClientId,
          ValidateAudience = true,
          ValidAudiences = [Issuer],
          ValidateLifetime = true,
          ValidateIssuerSigningKey = true,
          IssuerSigningKey = securityKey,
          RequireExpirationTime = true,
          ClockSkew = TimeSpan.Zero
        };

        try
        {
          var validationResult = handler.ValidateTokenAsync(clientAssertion, validationParams).GetAwaiter().GetResult();

          // Per RFC 7523 the client assertion's `iss` and `sub` are both the client id.
          return validationResult is not null && validationResult.IsValid && validationResult.ClaimsIdentity.HasClaim(c => c is { Type: "sub", Value: ClientId }) && validationResult.ClaimsIdentity.HasClaim(c => c.Type == "jti") && validationResult.ClaimsIdentity.HasClaim(c => c.Type == "iat");
        }
        catch (Exception)
        {
          return false;
        }
      }

      case "spiffe_jwt":
      {
        var requestBody = request.Content?.ReadAsStringAsync().GetAwaiter().GetResult();
        if (requestBody is null)
        {
          return false;
        }

        var body = ParseFormUrlEncodedString(requestBody);

        return body.TryGetValue("client_id", out var clientId) && clientId == ClientId &&
               body.TryGetValue("client_assertion_type", out var assertionType) && assertionType == "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe" &&
               body.TryGetValue("client_assertion", out var assertion) && assertion == SpiffeJwtSvid;
      }

      case "tls_client_auth" or "self_signed_tls_client_auth" or "spiffe_x509":
      {
        var noAuthHeader = request.Headers.Authorization is null;

        var requestBody = request.Content?.ReadAsStringAsync().GetAwaiter().GetResult();
        if (requestBody is null)
        {
          return false;
        }

        var body = ParseFormUrlEncodedString(requestBody);

        var hasOnlyClientId = body.TryGetValue("client_id", out var clientId) && clientId == ClientId && !body.ContainsKey("client_secret") && !body.ContainsKey("client_assertion") && !body.ContainsKey("client_assertion_type");

        return noAuthHeader && hasOnlyClientId;
      }

      default:
      {
        return false;
      }
    }
  }

  private static Dictionary<string, string> ParseFormUrlEncodedString(string encodedString)
  {
    var dictionary = new Dictionary<string, string>();
    if (string.IsNullOrEmpty(encodedString))
      return dictionary;

    var pairs = encodedString.Split('&');
    foreach (var pair in pairs)
    {
      var keyValue = pair.Split('=');
      if (keyValue.Length == 2)
      {
        var key = HttpUtility.UrlDecode(keyValue[0]);
        var value = HttpUtility.UrlDecode(keyValue[1]);
        dictionary[key] = value;
      }
    }

    return dictionary;
  }

  private static long ToUnixTimeStamp(DateTime dateTime)
  {
    return new DateTimeOffset(dateTime.ToUniversalTime()).ToUnixTimeSeconds();
  }
}
