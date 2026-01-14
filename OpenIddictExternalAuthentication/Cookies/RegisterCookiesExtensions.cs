using System;
using Microsoft.Extensions.DependencyInjection;
using Shaddix.OpenIddict.ExternalAuthentication.Handlers;

namespace Shaddix.OpenIddict.ExternalAuthentication.Cookies;

/// <summary>
/// Convenience extensions for OpenIddict
/// </summary>
public static class RegisterCookiesExtensions
{
    internal static CookiesConfiguration CookiesConfiguration { get; private set; }

    /// <summary>
    /// Adds support for clients with UseHttpOnlyCookies set to true
    /// Remember that calling this function is not enough, and you still need to configure the Client with `UseHttpOnlyCookies: true` in appsettings!
    /// </summary>
    public static OpenIddictBuilder AddSupportForHttpOnlyCookieClients(
        this OpenIddictBuilder openIddictBuilder,
        Action<CookiesConfiguration> configure = null
    )
    {
        var options = new CookiesConfiguration();
        configure?.Invoke(options);
        CookiesConfiguration = options;

        return openIddictBuilder
            .AddServer(options =>
            {
                options.AllowPasswordFlow().AllowRefreshTokenFlow();

                options
                    .AddEventHandler(StoreAccessRefreshTokenInCookieHandler.Descriptor)
                    .AddEventHandler(RemoveAccessRefreshTokenFromCookiesOnLogoutHandler.Descriptor)
                    .AddEventHandler(RefreshTokenFromCookiesHandler.Descriptor)
                    .AddEventHandler(CopyExtraParametersToResponse.Descriptor);
            })
            .AddValidation(options =>
            {
                options.AddEventHandler(AccessTokenFromCookiesHandler.Descriptor);
            });
    }
}
