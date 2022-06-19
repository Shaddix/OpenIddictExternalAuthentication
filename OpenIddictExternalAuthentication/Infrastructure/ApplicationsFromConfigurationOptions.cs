namespace Shaddix.OpenIddict.ExternalAuthentication.Infrastructure;

/// <summary>
/// Configuration options for <see cref="OpenIddictExtensions.UseOpenIdDictApplicationsFromConfiguration"/>
/// </summary>
public class ApplicationsFromConfigurationOptions
{
    /// <summary>
    /// PublicUrl will be prepended to relative URIs in 'RedirectUris' and 'PostLogoutRedirectUris'
    /// </summary>
    public string PublicUrl { get; set; }

    /// <summary>
    /// Sets the PublicUrl that will be prepended to relative URIs in 'RedirectUris' and 'PostLogoutRedirectUris'
    /// </summary>
    public ApplicationsFromConfigurationOptions SetPublicUrl(string publicUrl)
    {
        PublicUrl = publicUrl;
        return this;
    }
}
