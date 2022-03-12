using System.Collections.Generic;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddictExternalAuthentication.Example.Permissions;

namespace OpenIddictExternalAuthentication.Example.Controllers
{
    [Route("api/permissions")]
    [ApiController]
    public class PermissionExampleController : ControllerBase
    {
        [HttpGet("documents")]
        [Authorize]
        [PermissionAuthorize(Permission.DocumentManagement)]
        public ActionResult<IEnumerable<string>> GetDocuments()
        {
            return new string[] { "doc1", "doc2" };
        }

        [HttpGet("users")]
        [Authorize]
        [PermissionAuthorize(Permission.UserManagement)]
        public ActionResult<IEnumerable<string>> GetUsers()
        {
            return new string[] { "user1", "user2" };
        }
    }
}
