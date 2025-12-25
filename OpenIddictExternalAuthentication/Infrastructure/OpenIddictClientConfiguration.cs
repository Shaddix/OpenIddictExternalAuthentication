using OpenIddict.Abstractions;

namespace Shaddix.OpenIddict.ExternalAuthentication.Infrastructure;

/// <summary>
/// Configuration of a single Client
/// </summary>
public class OpenIddictClientConfiguration : OpenIddictApplicationDescriptor
{
    public const string SettingsUseHttpOnlyCookiesName = nameof(UseHttpOnlyCookies);
    public const string SettingsUseHttpOnlyCookiesKeepPayloadName = nameof(
        UseHttpOnlyCookiesKeepPayload
    );

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
    /// Do not return anything in payload.
    /// </summary>
    public bool? UseHttpOnlyCookies { get; set; }

    /// <summary>
    /// Stores RefreshToken and AccessToken in Http Only Cookie.
    /// Also returns AccessToken/RefreshToken in /connect/token payload
    /// </summary>
    public bool? UseHttpOnlyCookiesKeepPayload { get; set; }
}
