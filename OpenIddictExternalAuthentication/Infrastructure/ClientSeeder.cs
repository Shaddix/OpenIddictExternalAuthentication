using System;
using System.Collections.Generic;
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
                client.Type ??= "public";
                await _applicationManager.PopulateAsync(clientObject, client).ConfigureAwait(false);
                await _applicationManager.UpdateAsync(clientObject).ConfigureAwait(false);
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
