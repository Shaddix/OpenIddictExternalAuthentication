using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Shaddix.OpenIddict.ExternalAuthentication.Infrastructure;

/// <summary>
/// Helps in migrating from IdentityServer to OpenIdDict.
/// Rewrites some parameters/removes the scopes when it's not possible to do from the client side
/// (e.g. mobile apps)
/// </summary>
public class OpenIdDictConversionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly OpenIdDictConversionSettings _settings;
    private readonly IOpenIddictClientConfigurationProvider _clientConfigurationProvider;

    public OpenIdDictConversionMiddleware(
        RequestDelegate next,
        OpenIdDictConversionSettings settings,
        IOpenIddictClientConfigurationProvider clientConfigurationProvider
    )
    {
        _next = next;
        _settings = settings;
        _clientConfigurationProvider = clientConfigurationProvider;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var request = context.Request;
        if (request.Path.StartsWithSegments("/connect/token"))
        {
            var query = request.Form.Keys.ToDictionary(x => x, x => request.Form[x]);
            foreach (var (renameFrom, renameTo) in _settings.ParamsToRename)
            {
                if (query.ContainsKey(renameFrom))
                {
                    query[renameTo] = query[renameFrom];
                }
            }

            if (_settings.ShouldRemoveAuthorizationHeaderIfClientIdOrClientSecretIsPresent)
            {
                if (query.ContainsKey("client_secret") || query.ContainsKey("client_id"))
                {
                    request.Headers.Authorization = new StringValues();
                }
            }

            if (_settings.ShouldRemoveClientSecretForPublicClients)
            {
                RemoveClientSecretForPublicClients(query);
            }

            if (query.TryGetValue("scope", out var scopes))
            {
                var scopesAsString = scopes.ToString();
                foreach (var scope in _settings.ScopesToRemove)
                {
                    scopesAsString = scopesAsString.Replace(scope, "");
                }

                query["scope"] = new StringValues(scopesAsString.Trim());
            }

            request.Form = new FormCollection(query);
        }

        // Call the next delegate/middleware in the pipeline.
        await _next(context);
    }

    private void RemoveClientSecretForPublicClients(Dictionary<string, StringValues> query)
    {
        if (!query.ContainsKey("client_id"))
            return;
        var clientId = query["client_id"].ToString();
        if (_clientConfigurationProvider.TryGetConfiguration(clientId, out var client))
        {
            if (!string.IsNullOrEmpty(client.ClientSecret))
            {
                query.Remove("client_secret");
            }
        }
    }
}
