using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace OpenIddictExternalAuthentication.Example
{
    public class IdentityContext : IdentityDbContext<IdentityUser>
    {
        public IdentityContext(
            DbContextOptions options
        ) : base(options)
        {
        }
    }
}