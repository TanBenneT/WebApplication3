using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication3.ViewModels;

namespace WebApplication3.Pages
{
    public class Login2faModel : PageModel
    {
        private readonly UserManager<User> userManager;

        public Login2faModel(UserManager<User> userManager)
        {
            this.userManager = userManager;
        }

        [BindProperty]
        public string Code { get; set; }

        public void OnGet()
        {
        }
    }
}
