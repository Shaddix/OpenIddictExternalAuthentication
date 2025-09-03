using System;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using Shaddix.OpenIddict.ExternalAuthentication.Infrastructure;

namespace Shaddix.OpenIddict.ExternalAuthentication.Cookies;

public class StoreAccessRefreshTokenInCookieHandler
    : IOpenIddictServerHandler<OpenIddictServerEvents.ProcessSignInContext>
{
    public const string AccessTokenCookieName = "access_token";
    public const string RefreshTokenCookieName = "refresh_token";

    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IOpenIddictApplicationManager _applicationManager;

    /// <summary>
    /// Gets the default descriptor definition assigned to this handler.
    /// </summary>
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor
            .CreateBuilder<OpenIddictServerEvents.ProcessSignInContext>()
            .UseScopedHandler<StoreAccessRefreshTokenInCookieHandler>()
            .SetOrder(OpenIddictServerHandlers.AttachSignInParameters.Descriptor.Order + 10)
            .Build();

    public static readonly CookieOptions RefreshTokenCookieOption = new CookieOptions
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Strict,
        Path = "/connect/token",
    };

    public static readonly CookieOptions AccessTokenCookieOption = new CookieOptions
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Strict,
    };

    public StoreAccessRefreshTokenInCookieHandler(
        IHttpContextAccessor httpContextAccessor,
        IOpenIddictApplicationManager applicationManager
    )
    {
        _httpContextAccessor = httpContextAccessor;
        _applicationManager = applicationManager;
    }

    public async ValueTask HandleAsync(OpenIddictServerEvents.ProcessSignInContext context)
    {
        if (context.EndpointType != OpenIddictServerEndpointType.Token)
            return;

        var client = await _applicationManager.FindByClientIdAsync(context.ClientId);
        var settings = await _applicationManager.GetSettingsAsync(client);
        if (
            settings
                .GetValueOrDefault(
                    Infrastructure.OpenIddictClientConfiguration.SettingsUseHttpOnlyCookiesName
                )
                ?.ToLowerInvariant() == "true"
        )
        {
            // Set the refresh token in an HTTP-only cookie
            if (!string.IsNullOrEmpty(context.RefreshToken))
            {
                var cookieOption = new CookieOptions
                {
                    HttpOnly = RefreshTokenCookieOption.HttpOnly,
                    Secure = RefreshTokenCookieOption.Secure,
                    SameSite = RegisterCookiesExtensions.CookiesConfiguration.SameSite,
                    Path = RefreshTokenCookieOption.Path,
                };
                if (!RegisterCookiesExtensions.CookiesConfiguration.IsUseSessionCookie)
                {
                    var refreshTokenLifetime = settings.GetValueOrDefault(
                        OpenIddictConstants.Settings.TokenLifetimes.RefreshToken
                    );
                    cookieOption.Expires = !string.IsNullOrEmpty(refreshTokenLifetime)
                        ? DateTime.UtcNow.Add(TimeSpan.Parse(refreshTokenLifetime))
                        : DateTime.UtcNow.AddDays(14);
                }

                _httpContextAccessor.HttpContext.Response.Cookies.Append(
                    RefreshTokenCookieName,
                    context.RefreshToken,
                    cookieOption
                );
            }

            if (!string.IsNullOrEmpty(context.AccessToken))
            {
                var cookieOption = new CookieOptions
                {
                    HttpOnly = AccessTokenCookieOption.HttpOnly,
                    Secure = AccessTokenCookieOption.Secure,
                    SameSite = RegisterCookiesExtensions.CookiesConfiguration.SameSite,
                    Path = AccessTokenCookieOption.Path,
                };
                if (!RegisterCookiesExtensions.CookiesConfiguration.IsUseSessionCookie)
                {
                    var accessTokenLifetime = settings.GetValueOrDefault(
                        OpenIddictConstants.Settings.TokenLifetimes.AccessToken
                    );
                    cookieOption.Expires = !string.IsNullOrEmpty(accessTokenLifetime)
                        ? DateTime.UtcNow.Add(TimeSpan.Parse(accessTokenLifetime))
                        : DateTime.UtcNow.AddSeconds(3600);
                }

                _httpContextAccessor.HttpContext.Response.Cookies.Append(
                    AccessTokenCookieName,
                    context.AccessToken,
                    cookieOption
                );
            }

            // Remove the refresh token from the response
            var response = context.Transaction.Response;
            response.RemoveParameter(OpenIddictConstants.Parameters.RefreshToken);
            response.RemoveParameter(OpenIddictConstants.Parameters.AccessToken);
        }
    }
}
