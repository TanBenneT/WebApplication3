using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using WebApplication3.ViewModels;
using static System.Net.WebRequestMethods;

namespace WebApplication3.Pages
{
    [ValidateAntiForgeryToken]
    public class LoginModel : PageModel
    {
		private readonly SignInManager<User> signInManager;

        private readonly UserManager<User> userManager;

		[BindProperty]
		public Login LModel { get; set; }

		public LoginModel(SignInManager<User> signInManager, UserManager<User> userManager)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
        }
        public async Task<IActionResult> OnPostAsync()
		{
			if (ModelState.IsValid)
			{
                var valid = ValidateCaptcha();
                if (valid)
                {
					var identityResult = await signInManager.PasswordSignInAsync(LModel.Email, LModel.Password, LModel.RememberMe, true);
					if (identityResult.Succeeded)
					{
						var user = await userManager.FindByEmailAsync(LModel.Email);

						if (user != null)
						{
							string guid = Guid.NewGuid().ToString();
							HttpContext.Session.SetString("AuthToken", guid);
							Response.Cookies.Append("AuthToken", guid, new CookieOptions
							{
								HttpOnly = true,
								Secure = true,
								SameSite = SameSiteMode.Strict,
								Expires = DateTimeOffset.UtcNow.AddMinutes(5)
							});

							HttpContext.Session.SetString("UserEmail", user.Email);
							HttpContext.Session.SetString("FullName", user.FullName);
							HttpContext.Session.SetString("Gender", user.Gender);
							HttpContext.Session.SetString("MobileNo", user.MobileNo);
							HttpContext.Session.SetString("DeliveryAddress", user.DeliveryAddress);
							HttpContext.Session.SetString("AboutMe", user.AboutMe);


							var dataProtectionProvider = DataProtectionProvider.Create("EncryptData");
							var protector = dataProtectionProvider.CreateProtector("MySecretKey");

							HttpContext.Session.SetString("CreditCardNo", protector.Unprotect(user.CreditCardNo));
							HttpContext.Session.SetString("BirthDate", user.BirthDate.ToString());

							return RedirectToPage("Index");
						}

					}
					else if (identityResult.IsLockedOut)
					{
						ModelState.AddModelError("", "Account is locked. Please try again later or reset your password.");
						return Page();
					}
					else
					{
						ModelState.AddModelError("", "Username or Password incorrect");
					}
				}
			}
			return Page();
		}

        public bool ValidateCaptcha()
        {
            string Response = Request.Form["g-recaptcha-response"];
            bool valid = false;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create
            ("https://www.google.com/recaptcha/api/siteverify?secret=6Le5f1EpAAAAAD6Dgu9qOiml-3dJlNM9X01FI3Kj&response=" + Response);
            try
            {
                using (WebResponse wResponse = request.GetResponse())
                {
                    using (StreamReader readStream = new StreamReader(wResponse.GetResponseStream()))
                    {
                        string jsonResponse = readStream.ReadToEnd();

						var data = JsonSerializer.Deserialize<ReCaptchaResponse>(jsonResponse);

						valid = Convert.ToBoolean(data.success);
                    }
                }
                return valid;
            }
            catch (WebException ex)
            {
                throw ex;
            }

        }

		public void OnGet()
        {
        }
    }
}
