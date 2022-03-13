/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Authentication;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Shaddix.OpenIddict.ExternalAuthentication.Infrastructure;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Shaddix.OpenIddict.ExternalAuthentication;

/// <summary>
/// Default implementation of AuthorizationController that allows logging in via external login providers
/// </summary>
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
        IOpenIddictClientConfigurationProvider clientConfigurationProvider
    )
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _clientConfigurationProvider = clientConfigurationProvider;
    }

    /// <summary>
    /// Implements endpoint that external authentication should redirect to
    /// </summary>
    [AllowAnonymous]
    [HttpGet("~/connect/authorize/callback")]
    [HttpPost("~/connect/authorize/callback")]
    [IgnoreAntiforgeryToken]
    public virtual IActionResult ExternalCallback(string? remoteError, string originalQuery)
    {
        if (remoteError != null)
        {
            return BadRequest("Error from external provider. " + remoteError);
        }

        string redirectUrl = Url.Action(nameof(Authorize), ControllerName) + originalQuery;
        return LocalRedirect(redirectUrl!);
    }

    /// <summary>
    /// Implements authorize endpoint for Auth Code Flow
    /// </summary>
    [AllowAnonymous]
    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public virtual async Task<IActionResult> Authorize()
    {
        OpenIddictRequest? request = HttpContext.GetOpenIddictServerRequest();
        if (request == null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        ExternalLoginInfo externalLoginInfo = await _signInManager.GetExternalLoginInfoAsync();
        if (externalLoginInfo == null)
        {
            // If an identity provider was explicitly specified, redirect
            // the user agent to the AccountController.ExternalLogin action.
            OpenIddictParameter? providerParameter = request["provider"];
            if (providerParameter == null)
            {
                return Content("No external authentication provider was specified");
            }

            var provider = (string)providerParameter.Value!;

            var redirectUrl = Url.Action(
                nameof(ExternalCallback),
                ControllerName,
                new { originalQuery = HttpContext.Request.QueryString }
            );

            var properties = _signInManager.ConfigureExternalAuthenticationProperties(
                provider,
                redirectUrl
            );
            // Request a redirect to the external login provider.
            return Challenge(properties, provider);
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

            IIdentity? identity = authenticateResult.Principal.Identity;
            string? userName = identity!.Name;
            TUser user = await _userManager.FindByNameAsync(userName);

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
        else if (request.IsRefreshTokenGrantType())
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
                return Error("refresh_token_invalid");
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
        TUser? user = await CreateNewUser(externalLoginInfo);

        if (user == null)
        {
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
            && _clientConfigurationProvider.TryGetConfiguration(request.ClientId,
                out var configuration)
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

        await AddClaims(principal, user);

        var scopes = request.GetScopes();
        principal.SetScopes(scopes);

        foreach (var claim in principal.Claims)
        {
            claim.SetDestinations(GetDestinations(claim, principal));
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
    protected virtual async Task AddClaims(ClaimsPrincipal principal, TUser user)
    {
        IList<Claim> claims = await GetClaims(user);

        ClaimsIdentity claimIdentity = principal.Identities.First();
        claimIdentity.AddClaims(claims);
    }

    /// <summary>
    /// Returns claims that will be added to the user's principal (and later to JWT token).
    /// Consider overriding this function if you want to add more claims.
    /// </summary>
    protected virtual Task<IList<Claim>> GetClaims(TUser user)
    {
        return Task.FromResult(new List<Claim>()
        {
            new(JwtClaimTypes.NickName, user.UserName),
            new(JwtClaimTypes.Id, user.Id.ToString() ?? string.Empty),
            new(JwtClaimTypes.Subject, user.Id.ToString() ?? string.Empty),
        } as IList<Claim>);
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