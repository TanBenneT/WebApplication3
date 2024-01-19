using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Threading.Tasks;
using WebApplication3.ViewModels;

namespace WebApplication3.Pages
{
    [Authorize]
	[ValidateAntiForgeryToken]
	public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<User> userManager;
        private readonly SignInManager<User> signInManager;

        public ChangePasswordModel(UserManager<User> userManager, SignInManager<User> signInManager)
        {
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
				var isCurrentPasswordValid = await userManager.CheckPasswordAsync(user, ChangePassword.CurrentPassword);

				if (!isCurrentPasswordValid)
				{
					ModelState.AddModelError("ChangePassword.CurrentPassword", "Current password is incorrect.");
				}

				var changePasswordResult = await userManager.ChangePasswordAsync(user, ChangePassword.CurrentPassword, ChangePassword.ConfirmNewPassword);

                if (changePasswordResult.Succeeded)
                {
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
