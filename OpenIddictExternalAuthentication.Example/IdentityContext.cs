using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Shaddix.OpenIddict.ExternalAuthentication.Example;

public class IdentityContext : IdentityDbContext<IdentityUser>
{
    public DbSet<PersistedGrant> PersistedGrants { get; set; }

    public IdentityContext(DbContextOptions options) : base(options) { }
}
