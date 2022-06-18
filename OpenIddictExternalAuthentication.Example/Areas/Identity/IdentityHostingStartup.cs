using System;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Shaddix.OpenIddict.ExternalAuthentication.Example;

[assembly: HostingStartup(typeof(Shaddix.OpenIddict.ExternalAuthentication.Example.Areas.Identity.IdentityHostingStartup))]
namespace Shaddix.OpenIddict.ExternalAuthentication.Example.Areas.Identity
{
    public class IdentityHostingStartup : IHostingStartup
    {
        public void Configure(IWebHostBuilder builder)
        {
            builder.ConfigureServices((context, services) => {
            });
        }
    }
}
