using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using OpenIddictExternalAuthentication.Example.Permissions;

namespace OpenIddictExternalAuthentication.Example
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

            services.AddDbContext<IdentityContext>(
                options =>
                {
                    options.UseInMemoryDatabase("OAuthTest");
                    options.UseOpenIddict();
                });

            services
                .AddDefaultIdentity<IdentityUser>(
                    options =>
                    {
                        options.SignIn.RequireConfirmedAccount = false;
                        options.Lockout.AllowedForNewUsers = false;

                        // configure password security rules
                        Configuration.GetSection("OpenId:Password").Bind(options.Password);
                    }
                )
                .AddRoles<IdentityRole>()
                .AddRoleManager<RoleManager<IdentityRole>>()
                .AddEntityFrameworkStores<IdentityContext>()
                .AddDefaultTokenProviders();
            
            // Configure Identity to use the same JWT claims as OpenIddict instead
            // of the legacy WS-Federation claims it uses by default (ClaimTypes),
            // which saves you from doing the mapping in your authorization controller.
            services.Configure<IdentityOptions>(
                options =>
                {
                    options.ClaimsIdentity.UserNameClaimType = OpenIddictConstants.Claims.Name;
                    options.ClaimsIdentity.UserIdClaimType = OpenIddictConstants.Claims.Subject;
                    options.ClaimsIdentity.RoleClaimType = OpenIddictConstants.Claims.Role;
                    options.ClaimsIdentity.EmailClaimType = OpenIddictConstants.Claims.Email;
                }
            );
            services.AddOpenIddictConfigurations(Configuration);
            services
                .AddOpenIddict()
                .AddDefaultAuthorizationController()
                .AddCore(options =>
                {
                    options.UseEntityFrameworkCore()
                        .UseDbContext<IdentityContext>();
                })
                .AddServer(
                    options =>
                    {
                        options.DisableAccessTokenEncryption();

                        if (_webHostEnvironment.IsDevelopment())
                        {
                            options.UseAspNetCore().DisableTransportSecurityRequirement();
                        }

                        options.AddSigningCertificateFromConfiguration(Configuration);
                        options.AddEncryptionCertificateFromConfiguration(Configuration);
                    }
                )
                // Register the OpenIddict validation components.
                .AddValidation(
                    options =>
                    {
                        // Import the configuration from the local OpenIddict server instance.
                        options.UseLocalServer();

                        // Register the ASP.NET Core host.
                        options.UseAspNetCore();
                    }
                );

            services
                .AddAuthentication()
                .AddGoogle(
                    options => { Configuration.GetSection("Google").Bind(options); }
                )
                .AddFacebook(
                    options => { Configuration.GetSection("Facebook").Bind(options); }
                )
                .AddMicrosoftAccount(
                    options => { Configuration.GetSection("Microsoft").Bind(options); }
                )
                .AddGitHub(
                    options => { Configuration.GetSection("GitHub").Bind(options); }
                )
                .AddTwitter(
                    options => { Configuration.GetSection("Twitter").Bind(options); }
                )
                .AddOpenIdConnect(options => Configuration.Bind("AzureAd", options));

            // if you want to secure some controllers/actions within the same project with JWT
            // you need to configure something like the following
            services
                .AddAuthentication(
                    options =>
                    {
                        options.DefaultAuthenticateScheme =
                            OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
                        options.DefaultChallengeScheme =
                            OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
                    }
                );
            services.AddAuthorization();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
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

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseDefaultFiles();
            app.UseStaticFiles();
            app.UseEndpoints(
                endpoints =>
                {
                    endpoints.MapRazorPages();
                    endpoints.MapControllers();
                }
            );
            
            app.UseOpenIdDictApplicationsFromConfiguration().GetAwaiter().GetResult();
        }
    }
}