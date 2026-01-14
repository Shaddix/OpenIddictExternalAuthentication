#nullable enable
using System.Collections.Generic;

namespace Shaddix.OpenIddict.ExternalAuthentication.Infrastructure;

/// <summary>
/// Provides configurations for OpenId clients
/// </summary>
public interface IOpenIddictClientConfigurationProvider
{
    /// <summary>
    /// Returns configuration for passed clientId (and `true` as return or null if client is not found.
    /// </summary>
    bool TryGetConfiguration(string clientId, out OpenIddictClientConfiguration configuration);

    /// <summary>
    /// Returns configuration for all clients
    /// </summary>
    IList<OpenIddictClientConfiguration> GetAllConfigurations();
}
