namespace MonoCloud.Authentication.Api;

/// <summary>
/// Controls how certificate binding is validated for certificate-bound access tokens.
/// </summary>
public enum CertificateBindingValidation
{
  /// <summary>
  /// Validates certificate binding only when the token's <c>cnf</c> (confirmation) claim carries
  /// an <c>x5t#S256</c> thumbprint member.
  /// </summary>
  WhenPresent,

  /// <summary>
  /// Always validates certificate binding, rejecting tokens without a <c>cnf</c> claim.
  /// </summary>
  Required,

  /// <summary>
  /// Never validates certificate binding, even when the token carries a <c>cnf</c> claim.
  /// </summary>
  DangerouslyIgnore
}
