using System;
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
    private readonly IOpenIddictClientConfigurationProvider _clientConfigurationProvider;

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
        IOpenIddictClientConfigurationProvider clientConfigurationProvider
    )
    {
        _httpContextAccessor = httpContextAccessor;
        _clientConfigurationProvider = clientConfigurationProvider;
    }

    public ValueTask HandleAsync(OpenIddictServerEvents.ProcessSignInContext context)
    {
        if (context.EndpointType != OpenIddictServerEndpointType.Token)
            return ValueTask.CompletedTask;

        var clientConfiguration = _clientConfigurationProvider.GetConfiguration(context.ClientId);
        if (clientConfiguration.UseHttpOnlyCookies)
        {
            // Set the refresh token in an HTTP-only cookie
            if (!string.IsNullOrEmpty(context.RefreshToken))
            {
                var cookieOption = new CookieOptions
                {
                    HttpOnly = RefreshTokenCookieOption.HttpOnly,
                    Secure = RefreshTokenCookieOption.Secure,
                    SameSite = RefreshTokenCookieOption.SameSite,
                    Path = RefreshTokenCookieOption.Path,
                };
                if (!RegisterCookiesExtensions.CookiesConfiguration.IsUseSessionCookie)
                {
                    cookieOption.Expires = clientConfiguration.RefreshTokenLifetime.HasValue
                        ? DateTime.UtcNow.AddSeconds(clientConfiguration.RefreshTokenLifetime.Value)
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
                    SameSite = AccessTokenCookieOption.SameSite,
                    Path = AccessTokenCookieOption.Path,
                };
                if (!RegisterCookiesExtensions.CookiesConfiguration.IsUseSessionCookie)
                {
                    cookieOption.Expires = clientConfiguration.AccessTokenLifetime.HasValue
                        ? DateTime.UtcNow.AddSeconds(clientConfiguration.AccessTokenLifetime.Value)
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

        return ValueTask.CompletedTask;
    }
}
