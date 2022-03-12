#nullable enable
using System.Collections.Generic;

namespace OpenIddictExternalAuthentication;

public interface IOpenIddictConfigurationProvider
{
    OpenIddictClientConfiguration? GetConfiguration(string clientId);

    bool TryGetConfiguration(string clientId, out OpenIddictClientConfiguration configuration);

    IList<OpenIddictClientConfiguration> GetAllConfigurations();
}
