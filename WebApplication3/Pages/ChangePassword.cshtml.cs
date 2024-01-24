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

                var currentPasswordHash = user.PasswordHash;

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

				if (IsPasswordInHistory(user, ChangePassword.ConfirmNewPassword))
                {
                    ModelState.AddModelError("ChangePassword.ConfirmNewPassword", "New password cannot be the same as a previous passwords.");
                    return Page();
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

                    AddPasswordToHistory(user, currentPasswordHash);

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

        private bool IsPasswordInHistory(User user, string newPassword)
        {
            var userPasswordHistories = dbContext.PasswordHistories
                .Where(ph => ph.UserId == user.Id)
                .ToList();

            var passwordHasher = new PasswordHasher<User>();
            foreach (var passwordHistory in userPasswordHistories)
            {
                if (passwordHasher.VerifyHashedPassword(user, passwordHistory.HashedPassword, newPassword) == PasswordVerificationResult.Success)
                {
                    return true;
                }
            }

            return false;
        }


        private void AddPasswordToHistory(User user, string currentPassword)
        {
            var userPasswordHistories = dbContext.PasswordHistories
                .Where(ph => ph.UserId == user.Id)
                .ToList();

            var passwordHistory = new PasswordHistory
            {
                UserId = user.Id,
                HashedPassword = currentPassword,
                CreatedAt = DateTime.UtcNow
            };

            dbContext.PasswordHistories.Add(passwordHistory);

            if (userPasswordHistories.Count >= 2)
            {
                var entriesToRemove = userPasswordHistories.Skip(2).ToList();
                dbContext.PasswordHistories.RemoveRange(entriesToRemove);
            }

            dbContext.SaveChanges();
        }



    }
}
