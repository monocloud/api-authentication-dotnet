namespace MonoCloud.Authentication.Api.Shared;

internal class MtlsEndpointAliases
{
  [JsonPropertyName("token_endpoint")]
  public string? TokenEndpoint { get; set; }
  [JsonPropertyName("device_authorization_endpoint")]
  public string? DeviceAuthorizationEndpoint { get; set; }
  [JsonPropertyName("revocation_endpoint")]
  public string? RevocationEndpoint { get; set; }
  [JsonPropertyName("introspection_endpoint")]
  public string? IntrospectionEndpoint { get; set; }
}
