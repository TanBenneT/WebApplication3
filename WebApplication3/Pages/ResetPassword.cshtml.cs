using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.Net;
using System.Net.Http;
using System.Net.Mail;
using System.Text.Encodings.Web;
using System.Web;
using WebApplication3.ViewModels;

namespace WebApplication3.Pages
{
    [ValidateAntiForgeryToken]
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<User> userManager;

        public ResetPasswordModel(UserManager<User> userManager)
        {
            this.userManager = userManager;
        }

        [BindProperty]
        public string Email { get; set; }

        public async Task<IActionResult> OnPostAsync()
        {
            if (ModelState.IsValid)
            {
                var existingUser = await userManager.FindByEmailAsync(Email);
                if (existingUser == null)
                {
                    ModelState.AddModelError("Email", "Email Does Not Exist.");
                    return Page();
                }

				var resetLink = Url.Page(
				        "/ResetPasswordConfirmation",
				        pageHandler: null,
				        values: new { userId = existingUser.Id },
				        protocol: Request.Scheme);

				var client = new SmtpClient("smtp.gmail.com", 587)
                {
                    Credentials = new NetworkCredential("forschoolkenneth@gmail.com", "jnhd nwgr zfdk vmyr"),
                    EnableSsl = true
                };

                MailMessage mail = new MailMessage("freshfarmmarket@mail.com", Email, "Reset Password Link", $"Please reset your password by clicking here: <a href={HtmlEncoder.Default.Encode(resetLink)}>link</a>");
                mail.IsBodyHtml = true;
                client.Send(mail);
                return RedirectToPage("Login");
            }
            return Page();
        }

        public void OnGet()
        {
        }
    }
}
