using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.Security.Claims;
using WebApplication3.Model;
using WebApplication3.ViewModels;

namespace WebApplication3.Pages
{
    [Authorize]
    public class IndexModel : PageModel
    {
        private readonly AuthDbContext dbContext;
        private readonly UserManager<User> userManager;
        private readonly SignInManager<User> signInManager;

        public IndexModel(AuthDbContext dbContext, UserManager<User> userManager, SignInManager<User> signInManager)
        {
            this.dbContext = dbContext;
            this.userManager = userManager;
            this.signInManager = signInManager;
        }

        public async Task OnGetAsync()
        {
            var authTokenInSession = HttpContext.Session.GetString("AuthToken");
            var authTokenInCookie = Request.Cookies["AuthToken"];
            var user = await userManager.GetUserAsync(User);

            if (authTokenInSession == null || authTokenInCookie == null || authTokenInSession != authTokenInCookie)
            {
                var logEntry = new AuditLog
                {
                    UserId = user.Id,
                    Action = "Invalid Auth Token",
                    CreatedAt = DateTime.UtcNow,
                };
                dbContext.AuditLogs.Add(logEntry);
                await dbContext.SaveChangesAsync();

                user.AuthToken = null;
                await userManager.UpdateAsync(user);

                foreach (var cookieKey in Request.Cookies.Keys)
                {
                    Response.Cookies.Delete(cookieKey, new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = true,
                        SameSite = SameSiteMode.Strict,
                        Expires = DateTime.Now.AddMonths(-20)
                    });
                }

                await signInManager.SignOutAsync();
                RedirectToPage("Login");
            }
            else
            {
                if (user.AuthToken != authTokenInSession)
                {
                    if (user.LastPasswordChangeTime.HasValue)
                    {
                        var maxPasswordAge = TimeSpan.FromDays(90);
                        var timeSinceLastChange = DateTime.UtcNow - user.LastPasswordChangeTime.Value;

                        if (timeSinceLastChange > maxPasswordAge)
                        {
                            TempData["NeedChange"] = "Your password has expired. Please change your password.";
                            RedirectToPage("ChangePassword");
                        }
                    }

                    var log = new AuditLog
                    {
                        UserId = user.Id,
                        Action = "AuthToken Mismatch",
                        CreatedAt = DateTime.UtcNow,
                    };
                    dbContext.AuditLogs.Add(log);
                    await dbContext.SaveChangesAsync();

                    user.AuthToken = null;
                    await userManager.UpdateAsync(user);

                    foreach (var cookieKey in Request.Cookies.Keys)
                    {
                        Response.Cookies.Delete(cookieKey, new CookieOptions
                        {
                            HttpOnly = true,
                            Secure = true,
                            SameSite = SameSiteMode.Strict,
                            Expires = DateTime.Now.AddMonths(-20)
                        });
                    }

                    await signInManager.SignOutAsync();
                    RedirectToPage("Login");
                }
                HttpContext.Session.SetString("UserId", user.Id);
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

                var logEntry = new AuditLog
                {
                    UserId = user.Id,
                    Action = "Logged In Successfully",
                    CreatedAt = DateTime.UtcNow,
                };

                dbContext.AuditLogs.Add(logEntry);
                await dbContext.SaveChangesAsync();

                RedirectToPage("Index");
            }
        }
    }
}