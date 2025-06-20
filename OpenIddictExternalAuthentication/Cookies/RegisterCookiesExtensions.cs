using System;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Server;
using OpenIddict.Validation;
using Shaddix.OpenIddict.ExternalAuthentication.Infrastructure;

namespace Shaddix.OpenIddict.ExternalAuthentication.Cookies;

/// <summary>
/// Convenience extensions for OpenIddict
/// </summary>
public static class RegisterCookiesExtensions
{
    /// <summary>
    /// Adds support for clients with UseHttpOnlyCookies set to true
    /// Remember that calling this function is not enough, and you still need to configure the Client with `UseHttpOnlyCookies: true` in appsettings!
    /// </summary>
    public static OpenIddictBuilder AddSupportForHttpOnlyCookieClients(
        this OpenIddictBuilder openIddictBuilder
    )
    {
        return openIddictBuilder
            .AddServer(options =>
            {
                options.AllowPasswordFlow().AllowRefreshTokenFlow();

                options
                    .AddEventHandler<OpenIddictServerEvents.ProcessSignInContext>(
                        x =>
                            x.UseSingletonHandler<StoreAccessRefreshTokenInCookieHandler>()
                                .SetOrder(
                                    OpenIddictServerHandlers.AttachSignInParameters.Descriptor.Order
                                        + 10
                                )
                    )
                    .AddEventHandler<OpenIddictServerEvents.ProcessSignOutContext>(
                        x =>
                            x.UseSingletonHandler<RemoveAccessRefreshTokenFromCookiesOnLogoutHandler>()
                    )
                    .AddEventHandler<OpenIddictServerEvents.ValidateTokenRequestContext>(
                        x =>
                            x.UseSingletonHandler<RefreshTokenFromCookiesHandler>()
                                .SetOrder(
                                    OpenIddictServerHandlers
                                        .Exchange
                                        .ValidateRefreshTokenParameter
                                        .Descriptor
                                        .Order - 10
                                )
                    );
            })
            .AddValidation(options =>
            {
                options.AddEventHandler<OpenIddictValidationEvents.ProcessAuthenticationContext>(
                    x =>
                        x.UseSingletonHandler<AccessTokenFromCookiesHandler>()
                            .SetOrder(int.MinValue)
                );
            });
    }
}
