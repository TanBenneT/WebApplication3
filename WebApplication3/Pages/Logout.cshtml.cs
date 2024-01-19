using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication3.ViewModels;

namespace WebApplication3.Pages
{
	[Authorize]
    public class LogoutModel : PageModel
    {
		private readonly SignInManager<User> signInManager;
		public LogoutModel(SignInManager<User> signInManager)
		{
			this.signInManager = signInManager;
		}
		public void OnGet()
        {
        }

		public async Task<IActionResult> OnPostLogoutAsync()
		{
			await signInManager.SignOutAsync();
			HttpContext.Session.Clear();
			Response.Cookies.Delete("AuthToken");
			Response.Cookies.Delete(".AspNetCore.Session");
			return RedirectToPage("Login");
		}

		public async Task<IActionResult> OnPostDontLogoutAsync()
		{
			return RedirectToPage("Index");
		}
	}
}
