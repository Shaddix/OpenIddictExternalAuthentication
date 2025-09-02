using OpenIddict.Abstractions;

namespace Shaddix.OpenIddict.ExternalAuthentication.Infrastructure;

/// <summary>
/// Configuration of a single Client
/// </summary>
public class OpenIddictClientConfiguration : OpenIddictApplicationDescriptor
{
    public const string SettingsUseHttpOnlyCookiesName = nameof(UseHttpOnlyCookies);

    /// <summary>
    /// Lifetime of an access token in seconds (3600 by default)
    /// </summary>
    public int? AccessTokenLifetime { get; set; }

    /// <summary>
    /// Rolling lifetime of a refresh token in seconds (14 days by default)
    /// </summary>
    public int? RefreshTokenLifetime { get; set; }

    /// <summary>
    /// Stores RefreshToken and AccessToken in Http Only Cookie.
    /// Only returns AccessToken in /connect/token payload (Refresh Token is not returned)
    /// </summary>
    public bool UseHttpOnlyCookies { get; set; }
}
