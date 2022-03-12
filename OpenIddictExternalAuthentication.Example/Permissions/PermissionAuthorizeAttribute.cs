using System.Linq;
using Microsoft.AspNetCore.Authorization;

namespace OpenIddictExternalAuthentication.Example.Permissions
{
    public class PermissionAuthorizeAttribute : AuthorizeAttribute
    {
        internal const string PolicyPrefix = "PERMISSION:";

        /// <summary>
        /// Creates a new instance of <see cref="AuthorizeAttribute"/> class.
        /// </summary>
        /// <param name="permissions">A list of permissions to authorize</param>
        public PermissionAuthorizeAttribute(params Permission[] permissions)
        {
            Policy =
                $"{PolicyPrefix}{string.Join(",", permissions.Select(x => x.ToString()).ToArray())}";
        }
    }
}
