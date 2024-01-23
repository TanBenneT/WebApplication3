using Microsoft.AspNetCore.Identity;
using System;

namespace WebApplication3.ViewModels
{
    public class User : IdentityUser
    {
        public string FullName { get; set; }
        public string Gender { get; set; }
        public string MobileNo { get; set; }
        public string DeliveryAddress { get; set; }
        public string AboutMe { get; set; }
        public string CreditCardNo { get; set; }
        public string PhotoPath { get; set; }
        public DateTime? BirthDate { get; set; }
        public string? AuthToken { get; set; }
        public DateTime? LastPasswordChangeTime { get; set; }

        public List<PasswordHistory> PasswordHistories { get; set; }

    }
}

