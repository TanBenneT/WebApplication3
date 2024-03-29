﻿using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using WebApplication3.ViewModels;

namespace WebApplication3.Model
{

    public class AuthDbContext : IdentityDbContext<User>
    {
        private readonly IConfiguration _configuration;
        //public AuthDbContext(DbContextOptions<AuthDbContext> options):base(options){ }
        public AuthDbContext(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            string connectionString = _configuration.GetConnectionString("AuthConnectionString"); optionsBuilder.UseSqlServer(connectionString);
        }
        public DbSet<AuditLog> AuditLogs { get; set; }
        public DbSet<PasswordHistory> PasswordHistories { get; set; }

    }

}
