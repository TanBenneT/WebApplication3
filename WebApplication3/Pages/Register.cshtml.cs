using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.Encodings.Web;
using WebApplication3.ViewModels;

namespace WebApplication3.Pages
{
    [ValidateAntiForgeryToken]
    public class RegisterModel : PageModel
    {

        private UserManager<User> userManager { get; }
        private SignInManager<User> signInManager { get; }

        [BindProperty]
        public Register RModel { get; set; }

        public RegisterModel(UserManager<User> userManager,
        SignInManager<User> signInManager)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
        }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (ModelState.IsValid)
            {
                var existingUser = await userManager.FindByEmailAsync(RModel.Email);
                if (existingUser != null)
                {
                    ModelState.AddModelError("RModel.Email", "Email address is already registered.");
                    return Page();
                }

                if (RModel.Photo != null)
                {
                    string fileExtension = Path.GetExtension(RModel.Photo.FileName).ToLower();
                    if (fileExtension != ".jpg")
                    {
                        ModelState.AddModelError("RModel.Photo", "Please upload a JPG file.");
                        return Page();
                    }
                }
                var dataProtectionProvider = DataProtectionProvider.Create("EncryptData");
                var protector = dataProtectionProvider.CreateProtector("MySecretKey");

                var uploadsFolder = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "uploads");
                var filePath = Path.Combine(uploadsFolder, RModel.Photo.FileName);

                using (var fileStream = new FileStream(filePath, FileMode.Create))
                {
                    await RModel.Photo.CopyToAsync(fileStream);
                }

                var user = new User
                {
                    UserName = RModel.Email,
                    Email = RModel.Email,
                    FullName = RModel.FullName,
                    Gender = RModel.Gender,
                    MobileNo = RModel.MobileNo,
                    DeliveryAddress = RModel.DeliveryAddress,
                    AboutMe = HtmlEncoder.Default.Encode(RModel.AboutMe),
                    CreditCardNo = protector.Protect(RModel.CreditCardNo),
                    PhotoPath = filePath,
                    BirthDate = RModel.BirthDate,
                    LastPasswordChangeTime = DateTime.UtcNow,
                    EmailConfirmed = true,
                    TwoFactorEnabled = true
                };

                var result = await userManager.CreateAsync(user, RModel.Password);
                if (result.Succeeded)
                {
                    return RedirectToPage("Login");
                }
            }
            return Page();
        }
    }
}
