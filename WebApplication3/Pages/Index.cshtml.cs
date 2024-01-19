using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;

namespace WebApplication3.Pages
{
    [Authorize]
    public class IndexModel : PageModel
    {
        public void OnGet()
        {
			var authTokenInSession = HttpContext.Session.GetString("AuthToken");
			var authTokenInCookie = Request.Cookies["AuthToken"];

			if (authTokenInSession != null && authTokenInCookie != null && authTokenInSession != authTokenInCookie)
			{
				RedirectToPage("Login");
			}
		}
    }
}