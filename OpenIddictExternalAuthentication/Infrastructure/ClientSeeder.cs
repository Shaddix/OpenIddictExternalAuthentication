using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using OpenIddict.Abstractions;

namespace Shaddix.OpenIddict.ExternalAuthentication.Infrastructure;

public class ClientSeeder
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictClientConfigurationProvider _clientConfigurationProvider;

    public ClientSeeder(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictClientConfigurationProvider clientConfigurationProvider
    )
    {
        _applicationManager = applicationManager;
        _clientConfigurationProvider = clientConfigurationProvider;
    }

    /// <summary>
    /// Imports clients from <see cref="IOpenIddictClientConfigurationProvider"/> into OpenId database
    /// </summary>
    public async Task Seed(string publicUrl)
    {
        IList<OpenIddictClientConfiguration> clients =
            _clientConfigurationProvider.GetAllConfigurations();
        foreach (OpenIddictClientConfiguration client in clients)
        {
            if (!string.IsNullOrEmpty(publicUrl))
            {
                var baseUri = new Uri(publicUrl);
                PrependBaseUriToRelativeUris(client.RedirectUris, baseUri);
                PrependBaseUriToRelativeUris(client.PostLogoutRedirectUris, baseUri);
            }

            object clientObject = await _applicationManager
                .FindByClientIdAsync(client.ClientId!)
                .ConfigureAwait(false);
            // See OpenIddictConstants.Permissions for available permissions

            if (clientObject is null)
            {
                await _applicationManager.CreateAsync(client).ConfigureAwait(false);
            }
            else
            {
                if (string.IsNullOrEmpty(client.ClientType))
                {
                    if (string.IsNullOrEmpty(client.ClientSecret))
                    {
                        client.ClientType = "public";
                    }
                    else
                    {
                        client.ClientType = "confidential";
                    }
                }

                await _applicationManager.PopulateAsync(clientObject, client).ConfigureAwait(false);
                if (client.AccessTokenLifetime.HasValue)
                    client.Settings[OpenIddictConstants.Settings.TokenLifetimes.AccessToken] =
                        TimeSpan
                            .FromSeconds(client.AccessTokenLifetime.Value)
                            .ToString("c", CultureInfo.InvariantCulture);
                if (client.RefreshTokenLifetime.HasValue)
                    client.Settings[OpenIddictConstants.Settings.TokenLifetimes.RefreshToken] =
                        TimeSpan
                            .FromSeconds(client.RefreshTokenLifetime.Value)
                            .ToString("c", CultureInfo.InvariantCulture);

                client.Settings[OpenIddictClientConfiguration.SettingsUseHttpOnlyCookiesName] =
                    client.UseHttpOnlyCookies.ToString();

                await _applicationManager
                    .UpdateAsync(clientObject, client.ClientSecret ?? "")
                    .ConfigureAwait(false);
            }
        }
    }

    private static void PrependBaseUriToRelativeUris(HashSet<Uri> uris, Uri baseUri)
    {
        if (uris == null)
            return;

        List<Uri> relativeUris = uris.Where(x => !x.IsAbsoluteUri).ToList();
        foreach (var relativeUri in relativeUris)
        {
            uris.Remove(relativeUri);
            uris.Add(new Uri(baseUri, relativeUri));
        }
    }
}
