using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System;
using System.Diagnostics;
using System.Net;
using System.Net.Mail;
using System.Reflection;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using WebApplication3.Model;
using WebApplication3.ViewModels;
using static QRCoder.PayloadGenerator;
using static System.Net.WebRequestMethods;

namespace WebApplication3.Pages
{
    [ValidateAntiForgeryToken]
    public class LoginModel : PageModel
    {
		private readonly SignInManager<User> signInManager;

        private readonly UserManager<User> userManager;

        private readonly AuthDbContext dbContext;

        private readonly ILogger<LoginModel> logger;

        [BindProperty]
		public Login LModel { get; set; }

		public LoginModel(SignInManager<User> signInManager, UserManager<User> userManager, AuthDbContext dbContext, ILogger<LoginModel> logger)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
			this.dbContext = dbContext;
            this.logger = logger;
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
							});

                            user.AuthToken = guid;
                            await userManager.UpdateAsync(user);

                            var logEntry = new AuditLog
                            {
                                UserId = user.Id,
                                Action = "Logging In, New AuthToken Given",
                                CreatedAt = DateTime.UtcNow,
                            };

                            dbContext.AuditLogs.Add(logEntry);
                            dbContext.SaveChanges();

                            return RedirectToPage("Index");
						}

					}
                    else if (identityResult.RequiresTwoFactor)
                    {
                        var existingUser = await userManager.FindByEmailAsync(LModel.Email);
                        if (existingUser == null)
                        {
                            ModelState.AddModelError("Email", "Email Does Not Exist.");
                            return Page();
                        }

                        var code = await userManager.GenerateTwoFactorTokenAsync(existingUser, "Email");

                        var message = $"Your one-time verification code is: {code}";

                        var client = new SmtpClient("smtp.gmail.com", 587)
                        {
                            Credentials = new NetworkCredential("forschoolkenneth@gmail.com", "jnhd nwgr zfdk vmyr"),
                            EnableSsl = true
                        };

                        MailMessage mail = new MailMessage("freshfarmmarket@mail.com", LModel.Email, "2FA Code", message);
                        client.Send(mail);
                        return RedirectToPage("Login2fa", new {Email = LModel.Email});
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
