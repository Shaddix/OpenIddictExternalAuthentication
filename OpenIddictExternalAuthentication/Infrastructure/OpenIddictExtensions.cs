using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace Shaddix.OpenIddict.ExternalAuthentication.Infrastructure;

/// <summary>
/// Convenience extensions for OpenIddict
/// </summary>
public static class OpenIddictExtensions
{
    /// <summary>
    /// Configures openiddict with signing certificate from appsettings.json 
    /// </summary>
    public static void AddSigningCertificateFromConfiguration(
        this OpenIddictServerBuilder options,
        IConfiguration configuration,
        string configurationPath = "OpenId:SigningCertificate"
    )
    {
        var signingCertificate = configuration.GetValue<OpenIdCertificateInfo>(configurationPath);
        if (
            !string.IsNullOrEmpty(signingCertificate?.Password)
            && !string.IsNullOrEmpty(signingCertificate?.Base64Certificate)
        )
        {
            options.AddSigningCertificate(
                new MemoryStream(Convert.FromBase64String(signingCertificate.Base64Certificate)),
                signingCertificate.Password
            );
        }
        else
        {
            options.AddDevelopmentSigningCertificate();
        }
    }

    /// <summary>
    /// Configures openiddict with encryption certificate from appsettings.json 
    /// </summary>
    public static void AddEncryptionCertificateFromConfiguration(
        this OpenIddictServerBuilder options,
        IConfiguration configuration,
        string configurationPath = "OpenId:EncryptionCertificate"
    )
    {
        var encryptionCertificate = configuration.GetValue<OpenIdCertificateInfo>(
            configurationPath
        );
        if (
            !string.IsNullOrEmpty(encryptionCertificate?.Password)
            && !string.IsNullOrEmpty(encryptionCertificate?.Base64Certificate)
        )
        {
            options.AddEncryptionCertificate(
                new MemoryStream(Convert.FromBase64String(encryptionCertificate.Base64Certificate)),
                encryptionCertificate.Password
            );
        }
        else
        {
            options.AddDevelopmentEncryptionCertificate();
        }
    }

    /// <summary>
    /// Imports Application from appsettings.json into OpenId database
    /// </summary>
    public static async Task UseOpenIdDictApplicationsFromConfiguration(
        this IApplicationBuilder applicationBuilder
    )
    {
        using IServiceScope scope = applicationBuilder.ApplicationServices.CreateScope();
        IServiceProvider serviceProvider = scope.ServiceProvider;
        IOpenIddictApplicationManager manager =
            serviceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var configurationProvider =
            serviceProvider.GetRequiredService<IOpenIddictClientConfigurationProvider>();

        var clients = configurationProvider.GetAllConfigurations();

        foreach (var client in clients)
        {
            var clientObject = await manager.FindByClientIdAsync(client.ClientId!);
            // See OpenIddictConstants.Permissions for available permissions

            if (clientObject is null)
            {
                await manager.CreateAsync(client);
            }
            else
            {
                client.Type ??= "public";
                await manager.PopulateAsync(clientObject, client);
                await manager.UpdateAsync(clientObject);
            }
        }
    }

    /// <summary>
    /// Registers implementation of IOption&lt;OpenIddictConfiguration&gt; and IOpenIddictClientConfigurationProvider
    /// </summary>
    public static void AddOpenIddictConfigurations(
        this IServiceCollection services,
        IConfiguration configuration,
        string configurationSection = "OpenId"
    )
    {
        services
            .AddTransient<IOpenIddictClientConfigurationProvider,
                OpenIddictClientConfigurationProvider>();
        services.Configure<OpenIddictConfiguration>(
            configuration.GetSection($"{configurationSection}")
        );
    }

    /// <summary>
    /// Configures OpenIddict to use Token and Authorization endpoints 
    /// </summary>
    public static OpenIddictBuilder AddDefaultAuthorizationController(
        this OpenIddictBuilder openIddictBuilder
    )
    {
        return openIddictBuilder.AddServer(
            options =>
            {
                // Enable the token endpoint.
                options.SetTokenEndpointUris("/connect/token");
                options
                    .AllowAuthorizationCodeFlow()
                    .RequireProofKeyForCodeExchange()
                    .SetAuthorizationEndpointUris("/connect/authorize");

                // Enable the password flow.
                options.AllowPasswordFlow();
                options.AllowRefreshTokenFlow();

                options
                    .UseAspNetCore()
                    .EnableTokenEndpointPassthrough()
                    .EnableAuthorizationEndpointPassthrough();
            }
        );
    }
}