using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace Shaddix.OpenIddict.ExternalAuthentication.Cookies;

/// <summary>
/// Copies RefreshToken from Cookies to OpenId Request object
/// </summary>
public class RefreshTokenFromCookiesHandler
    : IOpenIddictServerHandler<OpenIddictServerEvents.ValidateTokenRequestContext>
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    /// <summary>
    /// Gets the default descriptor definition assigned to this handler.
    /// </summary>
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor
            .CreateBuilder<OpenIddictServerEvents.ValidateTokenRequestContext>()
            .UseSingletonHandler<RefreshTokenFromCookiesHandler>()
            .SetOrder(
                OpenIddictServerHandlers.Exchange.ValidateRefreshTokenParameter.Descriptor.Order
                    - 10
            )
            .Build();

    public RefreshTokenFromCookiesHandler(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public ValueTask HandleAsync(OpenIddictServerEvents.ValidateTokenRequestContext context)
    {
        // Check if the request is for token exchange and contains a refresh token grant type
        if (context.Request?.IsRefreshTokenGrantType() == true)
        {
            if (string.IsNullOrEmpty(context.Request.RefreshToken))
                // Read the refresh token from the cookie
                if (
                    _httpContextAccessor.HttpContext.Request.Cookies.TryGetValue(
                        StoreAccessRefreshTokenInCookieHandler.RefreshTokenCookieName,
                        out var refreshToken
                    )
                )
                {
                    context.Request.RefreshToken = refreshToken;
                }
        }

        return ValueTask.CompletedTask;
    }
}
