using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Shaddix.OpenIddict.ExternalAuthentication.Infrastructure;

/// <summary>
/// Allows to enable/disable certain features of OpenIddict
/// </summary>
public class OpenIddictSettings
{
    public OpenIddictSettings(OpenIddictServerBuilder openIddictServerBuilder)
    {
        OpenIddictServerBuilder = openIddictServerBuilder;
    }

    /// <summary>
    /// PublicUrl will be prepended to relative URIs in 'RedirectUris' and 'PostLogoutRedirectUris'
    /// </summary>
    public string PublicUrl { get; set; }

    /// <summary>
    /// Disables logout endpoint (/connect/logout is enabled by default)
    /// </summary>
    public bool IsLogoutEndpointDisabled { get; set; }

    /// <summary>
    /// Disables authorization code flow (/connect/authorize is enabled by default)
    /// </summary>
    public bool IsAuthorizeFlowDisabled { get; set; }

    /// <summary>
    /// Disables refresh token flow (via /connect/token, enabled by default)
    /// </summary>
    public bool IsRefreshTokenFlowDisabled { get; set; }

    /// <summary>
    /// Enables resource owner password flow (via /connect/token, disabled by default as not secure)
    /// </summary>
    public bool IsPasswordFlowAllowed { get; set; }

    /// <summary>
    /// Enables device code flow (via /connect/verify, disabled by default since it's not common)
    /// </summary>
    public bool IsDeviceCodeFlowAllowed { get; set; }

    public OpenIddictServerBuilder OpenIddictServerBuilder { get; set; }

    public IConfiguration Configuration { get; set; }

    /// <summary>
    /// Disables logout endpoint (/connect/logout is enabled by default)
    /// </summary>
    public OpenIddictSettings DisableLogoutEndpoint()
    {
        IsLogoutEndpointDisabled = true;
        return this;
    }

    /// <summary>
    /// Disables authorization code flow (/connect/authorize is enabled by default)
    /// </summary>
    public OpenIddictSettings DisableAuthorizeFlow()
    {
        IsAuthorizeFlowDisabled = true;
        return this;
    }

    /// <summary>
    /// Enables resource owner password flow (via /connect/token, disabled by default as not secure)
    /// </summary>
    public OpenIddictSettings AllowPasswordFlow()
    {
        IsPasswordFlowAllowed = true;
        return this;
    }

    /// <summary>
    /// Enables device code flow (via /connect/verify, disabled by default since it's not common)
    /// </summary>
    public OpenIddictSettings AllowDeviceCodeFlow()
    {
        IsDeviceCodeFlowAllowed = true;
        return this;
    }

    /// <summary>
    /// Disables refresh token flow (via /connect/token, enabled by default)
    /// </summary>
    public OpenIddictSettings DisableRefreshTokenFlow()
    {
        IsRefreshTokenFlowDisabled = true;
        return this;
    }

    /// <summary>
    /// Sets the Configuration section to configure OpenId clients
    /// </summary>
    /// <param name="configuration"></param>
    public OpenIddictSettings SetConfiguration(IConfiguration configuration)
    {
        Configuration = configuration;
        return this;
    }

    /// <summary>
    /// Sets the PublicUrl that will be prepended to relative URIs in 'RedirectUris' and 'PostLogoutRedirectUris'
    /// </summary>
    public OpenIddictSettings SetPublicUrl(string publicUrl)
    {
        PublicUrl = publicUrl;
        return this;
    }

    public bool IsScopeRegistrationDisabled { get; set; }

    /// <summary>
    /// Disables the call to options.RegisterScopes with available client scopes (enabled by default)
    /// </summary>
    public OpenIddictSettings DisableScopeRegistration()
    {
        IsScopeRegistrationDisabled = true;
        return this;
    }
}
