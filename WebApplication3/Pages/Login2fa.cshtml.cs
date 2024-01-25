using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.Net.Mail;
using System.Net;
using WebApplication3.ViewModels;
using System.Text.Json;
using WebApplication3.Model;

namespace WebApplication3.Pages
{
    [ValidateAntiForgeryToken]
    public class Login2faModel : PageModel
    {
        private readonly SignInManager<User> signInManager;
        private readonly UserManager<User> userManager;
        private readonly AuthDbContext dbContext;

        public Login2faModel(SignInManager<User> signInManager, UserManager<User> userManager, AuthDbContext dbContext)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this.dbContext = dbContext;
        }

        [BindProperty]
        public string Code { get; set; }

        public async Task<IActionResult> OnPostAsync(string Email)
        {
            if (ModelState.IsValid)
            {
                var valid = ValidateCaptcha();
                if (valid)
                {
                    var identityResult = await signInManager.TwoFactorSignInAsync("Email", Code, false, true);
                    if (identityResult.Succeeded)
                    {
                        var user = await userManager.FindByEmailAsync(Email);

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
                    else
                    {
                        return RedirectToPage("Login");
                    }
                }
            }
            return Page();
        }

        public async Task<IActionResult> OnGetAsync(string email)
        {
            if (email == null)
            {
                return RedirectToPage("Login");
            }

            var user = await userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return RedirectToPage("Login");

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
    }
}
