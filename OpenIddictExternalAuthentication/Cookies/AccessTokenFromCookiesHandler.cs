﻿using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIddict.Validation;

namespace Shaddix.OpenIddict.ExternalAuthentication.Cookies;

/// <summary>
/// Copies AccessToken from Cookies to OpenId Request object
/// </summary>
public class AccessTokenFromCookiesHandler
    : IOpenIddictValidationHandler<OpenIddictValidationEvents.ProcessAuthenticationContext>
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    /// <summary>
    /// Gets the default descriptor definition assigned to this handler.
    /// </summary>
    public static OpenIddictValidationHandlerDescriptor Descriptor { get; } =
        OpenIddictValidationHandlerDescriptor
            .CreateBuilder<OpenIddictValidationEvents.ProcessAuthenticationContext>()
            .UseSingletonHandler<AccessTokenFromCookiesHandler>()
            .SetOrder(int.MinValue)
            .Build();

    public AccessTokenFromCookiesHandler(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public ValueTask HandleAsync(OpenIddictValidationEvents.ProcessAuthenticationContext context)
    {
        if (string.IsNullOrEmpty(context.AccessToken))
        {
            if (
                _httpContextAccessor.HttpContext.Request.Cookies.TryGetValue(
                    StoreAccessRefreshTokenInCookieHandler.AccessTokenCookieName,
                    out var accessToken
                )
            )
            {
                context.AccessToken = accessToken;
            }
        }
        return ValueTask.CompletedTask;
    }
}
