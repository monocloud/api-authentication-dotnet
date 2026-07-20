namespace MonoCloud.Authentication.Api.Shared;

internal record ClaimLite(string Type, string Value);

internal class ClaimConverter : JsonConverter<Claim>
{
  public override Claim Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
  {
    var source = JsonSerializer.Deserialize<ClaimLite>(ref reader, options);
    var target = new Claim(source!.Type, source.Value);
    return target;
  }

  public override void Write(Utf8JsonWriter writer, Claim value, JsonSerializerOptions options) => JsonSerializer.Serialize(writer, new ClaimLite(value.Type, value.Value), options);
}
