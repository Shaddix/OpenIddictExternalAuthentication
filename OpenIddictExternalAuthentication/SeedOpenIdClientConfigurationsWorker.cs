using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Shaddix.OpenIddict.ExternalAuthentication.Infrastructure;

namespace Shaddix.OpenIddict.ExternalAuthentication;

/// <summary>
/// Worker that configures the Clients in OpenIddict according to the specified configuration
/// </summary>
public class SeedOpenIdClientConfigurationsWorker : IHostedService
{
    private readonly IServiceProvider _serviceProvider;

    public SeedOpenIdClientConfigurationsWorker(IServiceProvider serviceProvider) =>
        _serviceProvider = serviceProvider;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await _serviceProvider.SeedOpenIdClientsAsync();
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
