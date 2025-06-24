using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OpenIddict.Server;

namespace Shaddix.OpenIddict.ExternalAuthentication.Cookies;

public class RemoveAccessRefreshTokenFromCookiesOnLogoutHandler
    : IOpenIddictServerHandler<OpenIddictServerEvents.ProcessSignOutContext>
{
    public const string AccessTokenCookieName = "access_token";
    public const string RefreshTokenCookieName = "refresh_token";

    private readonly IHttpContextAccessor _httpContextAccessor;

    /// <summary>
    /// Gets the default descriptor definition assigned to this handler.
    /// </summary>
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor
            .CreateBuilder<OpenIddictServerEvents.ProcessSignOutContext>()
            .UseSingletonHandler<RemoveAccessRefreshTokenFromCookiesOnLogoutHandler>()
            // .SetOrder(OpenIddictServerHandlers.AttachSignInParameters.Descriptor.Order + 10)
            .Build();

    public RemoveAccessRefreshTokenFromCookiesOnLogoutHandler(
        IHttpContextAccessor httpContextAccessor
    )
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public ValueTask HandleAsync(OpenIddictServerEvents.ProcessSignOutContext context)
    {
        _httpContextAccessor.HttpContext.Response.Cookies.Delete(
            RefreshTokenCookieName,
            StoreAccessRefreshTokenInCookieHandler.RefreshTokenCookieOption
        );
        _httpContextAccessor.HttpContext.Response.Cookies.Delete(
            AccessTokenCookieName,
            StoreAccessRefreshTokenInCookieHandler.AccessTokenCookieOption
        );

        return ValueTask.CompletedTask;
    }
}
