using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using Shaddix.OpenIddict.ExternalAuthentication.Example.Permissions;
using Shaddix.OpenIddict.ExternalAuthentication.Infrastructure;

namespace Shaddix.OpenIddict.ExternalAuthentication.Example
{
    public class Startup
    {
        private readonly IWebHostEnvironment _webHostEnvironment;

        public Startup(IConfiguration configuration, IWebHostEnvironment webHostEnvironment)
        {
            _webHostEnvironment = webHostEnvironment;
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddSingleton<IAuthorizationPolicyProvider, AuthorizationPolicyProvider>();

            services.AddControllers();
            var sqliteFilename = "temp.db";
            services.AddDbContext<IdentityContext>(options =>
            {
                options.UseSqlite($"Data Source={sqliteFilename}");
                // options.UseNpgsql(
                //     $"Server=localhost;Database=openid_test;Port=5432;Username=postgres;Password=postgres;Pooling=true;Keepalive=5;Command Timeout=60;"
                // );
                options.UseOpenIddict();
            });

            services
                .AddDefaultIdentity<IdentityUser>(options =>
                {
                    options.SignIn.RequireConfirmedAccount = false;
                    options.Lockout.AllowedForNewUsers = false;

                    // configure password security rules
                    Configuration.GetSection("OpenId:Password").Bind(options.Password);
                })
                .AddRoles<IdentityRole>()
                .AddRoleManager<RoleManager<IdentityRole>>()
                .AddEntityFrameworkStores<IdentityContext>()
                .AddDefaultTokenProviders();

            // Configure Identity to use the same JWT claims as OpenIddict instead
            // of the legacy WS-Federation claims it uses by default (ClaimTypes),
            // which saves you from doing the mapping in your authorization controller.
            services.Configure<IdentityOptions>(options =>
            {
                options.ClaimsIdentity.UserNameClaimType = OpenIddictConstants.Claims.Name;
                options.ClaimsIdentity.UserIdClaimType = OpenIddictConstants.Claims.Subject;
                options.ClaimsIdentity.RoleClaimType = OpenIddictConstants.Claims.Role;
                options.ClaimsIdentity.EmailClaimType = OpenIddictConstants.Claims.Email;
            });

            var publicUrl = Configuration.GetSection("Auth").GetValue<string>("PublicHost");
            services
                .AddOpenIddict()
                .AddDefaultAuthorizationController(
                    options =>
                        options
                            .SetConfiguration(Configuration.GetSection("OpenId"))
                            .SetPublicUrl(publicUrl)
                            .EnableIdentityServerRefreshTokens<IdentityContext, IdentityUser>()
                )
                .AddCore(options =>
                {
                    options.UseEntityFrameworkCore().UseDbContext<IdentityContext>();
                })
                .AddServer(options =>
                {
                    options.DisableAccessTokenEncryption();

                    if (_webHostEnvironment.IsDevelopment())
                    {
                        options.UseAspNetCore().DisableTransportSecurityRequirement();
                    }
                })
                // Register the OpenIddict validation components.
                .AddValidation(options =>
                {
                    // Import the configuration from the local OpenIddict server instance.
                    options.UseLocalServer();

                    // Register the ASP.NET Core host.
                    options.UseAspNetCore();
                });

            services
                .AddAuthentication()
                .AddGoogle(options =>
                {
                    Configuration.GetSection("Google").Bind(options);
                })
                .AddFacebook(options =>
                {
                    Configuration.GetSection("Facebook").Bind(options);
                })
                .AddMicrosoftAccount(options =>
                {
                    Configuration.GetSection("Microsoft").Bind(options);
                })
                .AddGitHub(options =>
                {
                    Configuration.GetSection("GitHub").Bind(options);
                })
                .AddTwitter(options =>
                {
                    Configuration.GetSection("Twitter").Bind(options);
                })
                .AddOpenIdConnect(options => Configuration.Bind("AzureAd", options));

            // if you want to secure some controllers/actions within the same project with JWT
            // you need to configure something like the following
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme =
                    OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme =
                    OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
            });
            services.AddAuthorization();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            CreateDatabase(app).GetAwaiter().GetResult();
            app.SeedOpenIdClients();
            CreateUser(app).GetAwaiter().GetResult();

            var forwardedHeadersOptions = new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
            };
            forwardedHeadersOptions.KnownNetworks.Clear();
            forwardedHeadersOptions.KnownProxies.Clear();
            app.UseForwardedHeaders(forwardedHeadersOptions);

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseHttpsRedirection();
            }
            else
            {
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseRouting();

            app.UseOpenIdDictConversionMiddleware(
                new OpenIdDictConversionSettings() { ScopesToRemove = { "profile" } }
            );
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseDefaultFiles();
            app.UseStaticFiles();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorPages();
                endpoints.MapControllers();
            });
            app.UseSpa(spa =>
            {
                spa.Options.SourcePath = "wwwroot/react";
                // https://github.com/dotnet/aspnetcore/issues/3147#issuecomment-435617378
                spa.Options.DefaultPageStaticFileOptions = new StaticFileOptions()
                {
                    OnPrepareResponse = ctx =>
                    {
                        // Do not cache implicit `/index.html`
                        var headers = ctx.Context.Response.GetTypedHeaders();
                        headers.CacheControl = new CacheControlHeaderValue
                        {
                            Public = true,
                            MaxAge = TimeSpan.FromDays(0)
                        };
                    }
                };

                if (_webHostEnvironment.IsDevelopment())
                {
                    spa.UseProxyToSpaDevelopmentServer("http://localhost:3140/");
                }
            });
        }

        private async Task CreateDatabase(IApplicationBuilder app)
        {
            using var scope = app.ApplicationServices.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<IdentityContext>();
            await dbContext.Database.EnsureDeletedAsync();
            await dbContext.Database.MigrateAsync();
        }

        private async Task CreateUser(IApplicationBuilder app)
        {
            using var scope = app.ApplicationServices.CreateScope();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
            var dbContext = scope.ServiceProvider.GetRequiredService<IdentityContext>();

            var user = new IdentityUser("tst@gmail.com");
            await userManager.CreateAsync(user);
            await userManager.AddPasswordAsync(user, "123qweASD!");

            dbContext.PersistedGrants.Add(
                new PersistedGrant()
                {
                    Key = "123",
                    Type = "refresh_token",
                    ClientId = "web_client",
                    SubjectId = user.Id,
                    CreationTime = DateTime.UtcNow,
                    Expiration = DateTime.UtcNow.AddDays(1),
                }
            );
            await dbContext.SaveChangesAsync();
            var persistedGrants = await dbContext.PersistedGrants.ToListAsync();
            Console.WriteLine(JsonConvert.SerializeObject(persistedGrants));
        }
    }
}
