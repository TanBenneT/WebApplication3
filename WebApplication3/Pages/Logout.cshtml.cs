using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using WebApplication3.Model;
using WebApplication3.ViewModels;

namespace WebApplication3.Pages
{
	[Authorize]
    public class LogoutModel : PageModel
    {
		private readonly SignInManager<User> signInManager;
        private readonly AuthDbContext dbContext;
        private readonly UserManager<User> userManager;

        public LogoutModel(SignInManager<User> signInManager, AuthDbContext dbContext, UserManager<User> userManager)
        {
            this.signInManager = signInManager;
            this.dbContext = dbContext;
            this.userManager = userManager;
        }
        public void OnGet()
        {
        }

		public async Task<IActionResult> OnPostLogoutAsync()
        {
            var user = await userManager.GetUserAsync(User);

            var logEntry = new AuditLog
            {
                UserId = user.Id,
                Action = "Logged Out",
                CreatedAt = DateTime.UtcNow,
            };

            user.AuthToken = null;
            await userManager.UpdateAsync(user);

            await signInManager.SignOutAsync();
            HttpContext.Session.Clear();
			if (Request.Cookies[".AspNetCore.Session"] != null)
			{
                Response.Cookies.Append(".AspNetCore.Session", string.Empty, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
					Expires = DateTime.Now.AddMonths(-20)
                });
            }
            if (Request.Cookies["AuthToken"] != null)
            {
                Response.Cookies.Append("AuthToken", string.Empty, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTime.Now.AddMonths(-20)
                });
            }

            dbContext.AuditLogs.Add(logEntry);
            dbContext.SaveChanges();

            return RedirectToPage("Login");
		}

		public async Task<IActionResult> OnPostDontLogoutAsync()
		{
			return RedirectToPage("Index");
		}
	}
}
