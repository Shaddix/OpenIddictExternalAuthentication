/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

#nullable enable
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Authentication;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Shaddix.OpenIddict.ExternalAuthentication.Infrastructure;
using static OpenIddict.Abstractions.OpenIddictConstants;

[assembly: InternalsVisibleTo("OpenIddictExternalAuthentication.Tests")]

namespace Shaddix.OpenIddict.ExternalAuthentication;

/// <summary>
/// Default implementation of AuthorizationController that allows logging in via external login providers
/// </summary>
[ApiExplorerSettings(IgnoreApi = true)]
public abstract class OpenIdAuthorizationControllerBase<TUser, TKey> : Controller
    where TUser : IdentityUser<TKey>, new()
    where TKey : IEquatable<TKey>
{
    /// <summary>
    /// SignInManager
    /// </summary>
    protected readonly SignInManager<TUser> _signInManager;

    /// <summary>
    /// UserManager
    /// </summary>
    protected readonly UserManager<TUser> _userManager;

    private readonly IOpenIddictClientConfigurationProvider _clientConfigurationProvider;
    private readonly ILogger<OpenIdAuthorizationControllerBase<TUser, TKey>> _logger;

    /// <summary>
    /// Name of the controller to be used in URL generation.
    /// </summary>
    protected virtual string ControllerName => GetType().Name.Replace("Controller", "");

    /// <summary>
    /// Constructor for OpenIdAuthorizationControllerBase
    /// </summary>
    protected OpenIdAuthorizationControllerBase(
        SignInManager<TUser> signInManager,
        UserManager<TUser> userManager,
        IOpenIddictClientConfigurationProvider clientConfigurationProvider,
        ILogger<OpenIdAuthorizationControllerBase<TUser, TKey>> logger
    )
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _clientConfigurationProvider = clientConfigurationProvider;
        _logger = logger;
    }

    /// <summary>
    /// Implements logout endpoint
    /// </summary>
    /// <returns></returns>
    [HttpGet("~/connect/logout")]
    [ActionName(nameof(Logout)), HttpPost("~/connect/logout")]
    [AllowAnonymous]
    public virtual async Task<IActionResult> Logout()
    {
        // Ask ASP.NET Core Identity to delete the local and external cookies created
        // when the user agent is redirected from the external identity provider
        // after a successful authentication flow (e.g Google or Facebook).
        await _signInManager.SignOutAsync();

        // Returning a SignOutResult will ask OpenIddict to redirect the user agent
        // to the post_logout_redirect_uri specified by the client application or to
        // the RedirectUri specified in the authentication properties if none was set.
        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties { RedirectUri = "/" }
        );
    }

    /// <summary>
    /// Implements endpoint that external authentication should redirect to
    /// </summary>
    [AllowAnonymous]
    [HttpGet("~/connect/authorize/callback")]
    [HttpPost("~/connect/authorize/callback")]
    [IgnoreAntiforgeryToken]
    public virtual async Task<IActionResult> ExternalCallback(
        string? remoteError,
        string originalQuery
    )
    {
        _logger.LogInformation("User was redirected from external provider");
        if (remoteError != null)
        {
            return BadRequest("Error from external provider. " + remoteError);
        }

        if (!IsSpaRequest(originalQuery))
        {
            _logger.LogInformation("This is not a SPA call, will authorize and redirect");

            return await AuthorizeNonSpa(originalQuery);
        }
        else
        {
            _logger.LogInformation("Will redirect to {OriginalQuery}", originalQuery);

            string redirectUrl = Url.Action(nameof(Authorize), ControllerName) + originalQuery;

            return LocalRedirect(redirectUrl!);
        }
    }

    private static bool IsSpaRequest(string originalQuery)
    {
        Uri intermediateUri = CreateAbsoluteUriFromString(originalQuery);
        NameValueCollection queryString = System.Web.HttpUtility.ParseQueryString(
            intermediateUri.Query
        );
        return !string.IsNullOrEmpty(queryString.Get("client_id"));
    }

    private async Task<IActionResult> AuthorizeNonSpa(string returnUrl)
    {
        IActionResult Error(string message)
        {
            return RedirectToPage("./Login", new { ReturnUrl = returnUrl, ErrorMessage = message });
        }

        var externalLoginInfo = await _signInManager.GetExternalLoginInfoAsync();
        if (externalLoginInfo == null)
        {
            return Error("Error loading external login information.");
        }

        try
        {
            TUser? user = await _userManager.FindByLoginAsync(
                externalLoginInfo.LoginProvider,
                externalLoginInfo.ProviderKey
            );

            if (user == null)
            {
                try
                {
                    user = await CreateUserFromExternalInfo(externalLoginInfo);
                }
                catch (Exception e)
                {
                    return Error(e.Message);
                }
            }

            await _signInManager.SignInAsync(user, false, externalLoginInfo.LoginProvider);
        }
        catch (Exception e)
        {
            return Error(e.Message);
        }

        return LocalRedirect(returnUrl);
    }

    /// <summary>
    /// Redirects to external login provider
    /// </summary>
    [AllowAnonymous]
    [HttpGet("~/connect/authorize/redirect")]
    [HttpPost("~/connect/authorize/redirect")]
    [IgnoreAntiforgeryToken]
    public virtual IActionResult ExternalRedirect([FromForm] string provider, string returnUrl)
    {
        _logger.LogInformation(
            "Will redirect to external login provider {Provider}, return url: {ReturnUrl}",
            provider,
            returnUrl
        );

        returnUrl = AdjustReturnUrl(returnUrl, provider);

        _logger.LogInformation("Full return url: {ReturnUrl}", returnUrl);

        // If an identity provider was explicitly specified, redirect
        // the user agent to the AccountController.ExternalLogin action.
        var redirectUrl = Url.Action(
            nameof(ExternalCallback),
            ControllerName,
            new { originalQuery = returnUrl }
        );

        var properties = _signInManager.ConfigureExternalAuthenticationProperties(
            provider,
            redirectUrl
        );
        return Challenge(properties, provider);
    }

    internal static string AdjustReturnUrl(string returnUrl, string provider)
    {
        // returnUrl could look like:
        // - '/' (when opening login form directly
        // - '?client_id=web_client&redirect_uri=https%3A%2F%2Flocalhost%3A5001%2Findex.html%3Fauth-callback%3D1&response_type=code&scope=offline_access&state=...&code_challenge=...&code_challenge_method=S256&response_mode=query&prompt=login&display=popup&provider=Google'
        //      when opening via button from SPA
        // - '?client_id=web_client&redirect_uri=https%3A%2F%2Flocalhost%3A5001%2Findex.html%3Fauth-callback%3D1&response_type=code&scope=offline_access&state=...&code_challenge=...&code_challenge_method=S256&response_mode=query&prompt=login&display=popup'
        //      (without &provider=Google at the end) when opening from SPA via 'Internal' button, i.e. without specifying the provider
        // - null (define when!)

        returnUrl ??= "";
        if (!IsSpaRequest(returnUrl))
        {
            return returnUrl;
        }

        Uri intermediateUri = CreateAbsoluteUriFromString(returnUrl);

        NameValueCollection queryString = System.Web.HttpUtility.ParseQueryString(
            intermediateUri.Query
        );
        queryString.Set("provider", provider);

        UriBuilder builder = new UriBuilder(intermediateUri) { Query = queryString.ToString() };

        returnUrl = builder.Uri.Query;
        return returnUrl;
    }

    private static Uri CreateAbsoluteUriFromString(string returnUrl)
    {
        var uri = new Uri(returnUrl, UriKind.RelativeOrAbsolute);
        if (!uri.IsAbsoluteUri)
        {
            // We append a dummy host to construct a valid URI.
            // We will actually use only PathAndQuery
            uri = new Uri("http://localhost" + (returnUrl.StartsWith('/') ? "" : "/") + returnUrl);
        }

        return uri;
    }

    /// <summary>
    /// Implements authorize endpoint for Auth Code Flow
    /// </summary>
    /// <param name="provider">name of external authentication provider (e.g. 'Google', 'Facebook', etc). Casing matters!</param>
    [AllowAnonymous]
    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public virtual async Task<IActionResult> Authorize(string? provider)
    {
        _logger.LogInformation("Authorizing with provider {Provider}", provider);

        OpenIddictRequest? request = HttpContext.GetOpenIddictServerRequest();
        if (request == null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (string.IsNullOrEmpty(provider))
        {
            return await AuthorizeUsingDefaultSettings(
                request,
                IdentityConstants.ApplicationScheme
            );
        }

        ExternalLoginInfo externalLoginInfo = await _signInManager.GetExternalLoginInfoAsync();
        if (
            externalLoginInfo == null
            || (request.HasPrompt(Prompts.Login) && externalLoginInfo.LoginProvider != provider)
        )
        {
            return ExternalRedirect(provider, HttpContext.Request.QueryString.ToString());
        }

        try
        {
            TUser? user = await _userManager.FindByLoginAsync(
                externalLoginInfo.LoginProvider,
                externalLoginInfo.ProviderKey
            );

            if (user == null)
            {
                try
                {
                    user = await CreateUserFromExternalInfo(externalLoginInfo);
                }
                catch (Exception e)
                {
                    return Error(e.Message);
                }
            }

            return await SignInUser(user, request);
        }
        catch (Exception)
        {
            return BadRequest();
        }
    }

    /// <summary>
    /// Tries to authorize the user user built-in method without using any specific provider.
    /// Usually this means showing an authentication form.
    /// </summary>
    protected virtual async Task<IActionResult> AuthorizeUsingDefaultSettings(
        OpenIddictRequest request,
        string scheme
    )
    {
        var forcePrompt = request.HasPrompt(Prompts.Login);
        AuthenticateResult? info = null;
        if (!forcePrompt)
        {
            info = await HttpContext.AuthenticateAsync(scheme);
        }

        if (forcePrompt || !info.Succeeded)
        {
            var parameters = Request.HasFormContentType
                ? Request.Form.Where(parameter => parameter.Key != Parameters.Prompt).ToList()
                : Request.Query.Where(parameter => parameter.Key != Parameters.Prompt).ToList();

            // redirect to authentication
            return Challenge(
                authenticationSchemes: scheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = Request.PathBase + Request.Path + QueryString.Create(parameters)
                }
            );
        }

        // Retrieve the user profile corresponding to the refresh token.
        // Note: if you want to automatically invalidate the refresh token
        // when the user password/roles change, use the following line instead:
        // var user = _signInManager.ValidateSecurityStampAsync(info.Principal);
        var user = await _userManager.GetUserAsync(info.Principal);

        // Ensure the user is still allowed to sign in.
        if (!await _signInManager.CanSignInAsync(user))
        {
            return StandardError();
        }

        return await SignInUser(user, request);
    }

    /// <summary>
    /// Implements token endpoint for all auth flows
    /// </summary>
    [AllowAnonymous]
    [HttpPost("~/connect/token"), Produces("application/json")]
    public virtual async Task<IActionResult> Exchange()
    {
        OpenIddictRequest? request = HttpContext.GetOpenIddictServerRequest();
        if (request == null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (request.IsAuthorizationCodeGrantType())
        {
            var authenticateResult = await HttpContext.AuthenticateAsync(
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
            );
            if (!authenticateResult.Succeeded)
            {
                return StandardError();
            }

            TUser? user = await _userManager.GetUserAsync(authenticateResult.Principal);

            return await SignInUser(user, request);
        }
        else if (request.IsPasswordGrantType())
        {
            var user = await _userManager.FindByNameAsync(request.Username);
            if (user == null)
            {
                return StandardError();
            }

            // Validate the username/password parameters and ensure the account is not locked out.
            var result = await _signInManager.CheckPasswordSignInAsync(
                user,
                request.Password,
                lockoutOnFailure: true
            );
            if (!result.Succeeded)
            {
                return StandardError();
            }

            return await SignInUser(user, request);
        }
        else if (request.IsRefreshTokenGrantType() || request.IsDeviceCodeGrantType())
        {
            // Retrieve the claims principal stored in the refresh token.
            var info = await HttpContext.AuthenticateAsync(
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
            );

            // Retrieve the user profile corresponding to the refresh token.
            // Note: if you want to automatically invalidate the refresh token
            // when the user password/roles change, use the following line instead:
            // var user = _signInManager.ValidateSecurityStampAsync(info.Principal);
            var user = await _userManager.GetUserAsync(info.Principal);
            if (user == null)
            {
                if (request.IsRefreshTokenGrantType())
                {
                    return Error("refresh_token_invalid");
                }
                else if (request.IsDeviceCodeGrantType())
                {
                    return Error("device_code_invalid");
                }
                else
                {
                    return Error("token_invalid");
                }
            }

            // Ensure the user is still allowed to sign in.
            if (!await _signInManager.CanSignInAsync(user))
            {
                return StandardError();
            }

            return await SignInUser(user, request);
        }

        throw new NotImplementedException("The specified grant type is not implemented.");
    }

    /// <summary>
    /// Creates Asp.Net Identity user based on information from external auth provider.
    /// Links this external login to created account.
    /// To customize the created <typeparamref name="TUser"/> instance consider overriding <see cref="CreateNewUser"/>
    /// </summary>
    protected virtual async Task<TUser> CreateUserFromExternalInfo(
        ExternalLoginInfo externalLoginInfo
    )
    {
        _logger.LogInformation(
            "Creating new user, provider: {Provider}, displayName: {DisplayName}, provider key: {ProviderKey}",
            externalLoginInfo.LoginProvider,
            externalLoginInfo.ProviderDisplayName,
            externalLoginInfo.ProviderKey
        );

        TUser? user = await CreateNewUser(externalLoginInfo);

        if (user == null)
        {
            _logger.LogWarning(
                "Failed to create the user, provider: {Provider}, displayName: {DisplayName}, provider key: {ProviderKey}",
                externalLoginInfo.LoginProvider,
                externalLoginInfo.ProviderDisplayName,
                externalLoginInfo.ProviderKey
            );
            throw new AuthenticationException("login_not_allowed");
        }

        var identityResult = await _userManager.CreateAsync(user);
        if (!identityResult.Succeeded)
        {
            throw new AuthenticationException(string.Join(";", identityResult.Errors));
        }

        await _userManager.AddLoginAsync(user, externalLoginInfo);

        return user;
    }

    /// <summary>
    /// This function will be called when new user is trying to login using external auth provider.
    /// Override this function to customize the created User instance.
    /// Return null if you don't want to create a User
    /// </summary>
    /// <param name="externalUserInfo">User information from external OAuth provider</param>
    protected virtual Task<TUser?> CreateNewUser(ExternalLoginInfo externalUserInfo)
    {
        return Task.FromResult(new TUser() { UserName = GetUserName(externalUserInfo), })!;
    }

    /// <summary>
    /// ASP.Net Identity requires UserName field to be filled.
    /// So you have to provide UserName for newly created users.
    /// By default it's `externalUserInfo.LoginProvider_externalUserInfo.ProviderKey`.
    /// </summary>
    /// <param name="externalUserInfo">User information from OAuth provider</param>
    protected virtual string GetUserName(ExternalLoginInfo externalUserInfo) =>
        externalUserInfo.LoginProvider + "_" + externalUserInfo.ProviderKey;

    /// <summary>
    /// Returns the ActionResult that is later converted by OpenIddict into a JWT token.
    /// Sets up accesstoken/refreshtoken timeouts, add claims to the tokens.
    /// </summary>
    protected virtual async Task<IActionResult> SignInUser(TUser user, OpenIddictRequest? request)
    {
        if (request == null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        var principal = await _signInManager.CreateUserPrincipalAsync(user);
        if (
            !string.IsNullOrEmpty(request.ClientId)
            && _clientConfigurationProvider.TryGetConfiguration(
                request.ClientId,
                out var configuration
            )
        )
        {
            if (configuration.RefreshTokenLifetime != null)
            {
                principal.SetRefreshTokenLifetime(
                    TimeSpan.FromSeconds(configuration.RefreshTokenLifetime.Value)
                );
            }

            if (configuration.AccessTokenLifetime != null)
            {
                principal.SetAccessTokenLifetime(
                    TimeSpan.FromSeconds(configuration.AccessTokenLifetime.Value)
                );
            }
        }

        await AddClaims(principal, user, request);

        var scopes = request.GetScopes();
        principal.SetScopes(scopes);

        _logger.LogInformation(
            "New token created for user {UserId}, scopes: {scopes}",
            user.Id,
            string.Join(", ", scopes)
        );
        foreach (var claim in principal.Claims)
        {
            claim.SetDestinations(GetDestinations(claim, principal));
        }

        if (!await _signInManager.CanSignInAsync(user))
        {
            return Error("signin_requirements_not_met");
        }

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    /// <summary>
    /// Default error that is returned in case of authentication error
    /// </summary>
    protected virtual IActionResult StandardError()
    {
        return Error("invalid_username_or_password");
    }

    /// <summary>
    ///  Customized error that is returned in case of authentication error
    /// </summary>
    protected virtual IActionResult Error(string description)
    {
        var properties = new AuthenticationProperties(
            new Dictionary<string, string>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description
            }!
        );

        return Forbid(properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    /// <summary>
    /// Adds claims from <param name="user"/> to <param name="principal"/>.
    /// Override this function if you want to remove/modify some pre-added claims.
    /// If you just want to add more claims, consider overriding <see cref="GetClaims"/>
    /// </summary>
    protected virtual async Task AddClaims(
        ClaimsPrincipal principal,
        TUser user,
        OpenIddictRequest openIddictRequest
    )
    {
        IList<Claim> claims = await GetClaims(user, openIddictRequest);

        ClaimsIdentity claimIdentity = principal.Identities.First();
        claimIdentity.AddClaims(claims);
    }

    /// <summary>
    /// Returns claims that will be added to the user's principal (and later to JWT token).
    /// Consider overriding this function if you want to add more claims.
    /// </summary>
    protected virtual Task<IList<Claim>> GetClaims(TUser user, OpenIddictRequest openIddictRequest)
    {
        return Task.FromResult(
            new List<Claim>()
            {
                new(JwtClaimTypes.NickName, user.UserName),
                new(JwtClaimTypes.Id, user.Id.ToString() ?? string.Empty),
                new(JwtClaimTypes.Subject, user.Id.ToString() ?? string.Empty),
            } as IList<Claim>
        );
    }

    /// <summary>
    /// Returns destinations to which a certain claim could be returned
    /// </summary>
    protected virtual IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
    {
        // Note: by default, claims are NOT automatically included in the access and identity tokens.
        // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
        // whether they should be included in access tokens, in identity tokens or in both.
        switch (claim.Type)
        {
            case Claims.Name:
                yield return Destinations.AccessToken;

                if (principal.HasScope(Scopes.Profile))
                    yield return Destinations.IdentityToken;

                yield break;

            case Claims.Email:
                yield return Destinations.AccessToken;

                if (principal.HasScope(Scopes.Email))
                    yield return Destinations.IdentityToken;

                yield break;

            case Claims.Role:
                yield return Destinations.AccessToken;

                if (principal.HasScope(Scopes.Roles))
                    yield return Destinations.IdentityToken;

                yield break;

            // Never include the security stamp in the access and identity tokens, as it's a secret value.
            case "AspNet.Identity.SecurityStamp":
                yield break;

            default:
                yield return Destinations.AccessToken;
                yield break;
        }
    }
}
