using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication3.Model;
using WebApplication3.ViewModels;

namespace WebApplication3.Pages
{
	[ValidateAntiForgeryToken]
    public class ResetPasswordConfirmationModel : PageModel
    {
		private readonly UserManager<User> userManager;
		private readonly AuthDbContext dbContext;

		public ResetPasswordConfirmationModel(UserManager<User> userManager, AuthDbContext dbContext)
		{
			this.dbContext = dbContext;
			this.userManager = userManager;
		}

		[BindProperty]
		public ResetPassword ResetPassword { get; set; }

		public async Task<IActionResult> OnGetAsync(string userId, string token)
		{
			if (userId == null || token == null)
			{
				return RedirectToPage("Login");
			}

			var user = await userManager.FindByIdAsync(userId);
			if (user == null)
			{
				return RedirectToPage("Login");

			}

			return Page();
		}

		public async Task<IActionResult> OnPostAsync(string userId, string token)
		{
			if (ModelState.IsValid)
			{

				var user = await userManager.FindByIdAsync(userId);
				if (user == null)
				{
					return NotFound();
				}

				var currentPasswordHash = user.PasswordHash;

				if (IsPasswordInHistory(user, ResetPassword.ConfirmNewPassword))
				{
					ModelState.AddModelError("ResetPassword.ConfirmNewPassword", "New password cannot be the same as a previous passwords.");
					return Page();
				}

				var changePasswordResult = await userManager.ResetPasswordAsync(user, token, ResetPassword.ConfirmNewPassword);

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

					return RedirectToPage("Login");
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
