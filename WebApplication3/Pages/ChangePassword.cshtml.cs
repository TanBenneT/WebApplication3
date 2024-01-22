using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;
using WebApplication3.Model;
using WebApplication3.ViewModels;

namespace WebApplication3.Pages
{
    [Authorize]
	[ValidateAntiForgeryToken]
	public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<User> userManager;
        private readonly SignInManager<User> signInManager;
        private readonly AuthDbContext dbContext;

        public ChangePasswordModel(UserManager<User> userManager, SignInManager<User> signInManager, AuthDbContext dbContext)
        {
            this.dbContext = dbContext;
            this.userManager = userManager;
            this.signInManager = signInManager;
        }

        [BindProperty]
        public ChangePassword ChangePassword { get; set; }

        public void OnGet()
        {
        
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (ModelState.IsValid)
            {
                var user = await userManager.GetUserAsync(User);
                if (user == null)
                {
                    return NotFound();
                }

                if (TempData["NeedChange"] != null)
                {
                    ModelState.AddModelError(string.Empty, TempData["NeedChange"].ToString());
                    return Page();
                }
				var isCurrentPasswordValid = await userManager.CheckPasswordAsync(user, ChangePassword.CurrentPassword);

				if (!isCurrentPasswordValid)
				{
					ModelState.AddModelError("ChangePassword.CurrentPassword", "Current password is incorrect.");
                    return Page();
                }

                if (user.LastPasswordChangeTime.HasValue)
                {
                    var minPasswordAge = TimeSpan.FromMinutes(30);
                    var timeSinceLastChange = DateTime.UtcNow - user.LastPasswordChangeTime.Value;

                    if (timeSinceLastChange <= minPasswordAge)
                    {
                        ModelState.AddModelError("ChangePassword.CurrentPassword", $"Cannot change password within {minPasswordAge.TotalMinutes} minutes from the last change.");
                        return Page();
                    }
                }

                var changePasswordResult = await userManager.ChangePasswordAsync(user, ChangePassword.CurrentPassword, ChangePassword.ConfirmNewPassword);

                if (changePasswordResult.Succeeded)
                {
                    var logEntry = new AuditLog
                    {
                        UserId = user.Id,
                        Action = "Changed Password Successfully",
                        CreatedAt = DateTime.UtcNow,
                    };

                    dbContext.AuditLogs.Add(logEntry);
                    dbContext.SaveChanges();

                    user.LastPasswordChangeTime = DateTime.UtcNow;
                    await userManager.UpdateAsync(user);

                    await signInManager.RefreshSignInAsync(user);
                    return RedirectToPage("/Index");
                }

                foreach (var error in changePasswordResult.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }
            return Page();
        }
    }
}
