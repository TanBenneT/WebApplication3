﻿using System.Text.Json.Serialization;

namespace WebApplication3.ViewModels
{
    public class PasswordHistory
    {
        public int Id { get; set; }

        public string UserId { get; set; }

        public string HashedPassword { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.Now;
    }
}
