using Microsoft.AspNetCore.Mvc;

namespace OpenIddictExternalAuthentication.Example.Controllers
{
    public class HomeController : Controller
    {
        [HttpGet("/")]
        public IActionResult Index()
        {
            return View();
        }
    }
}
