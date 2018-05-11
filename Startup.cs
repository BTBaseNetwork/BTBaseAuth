﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BTBaseServices;
using BTBaseServices.DAL;
using BTBaseServices.Models;
using BTBaseServices.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace BTBaseAuth
{
    public class Startup
    {
        public static readonly string SERVER_NAME = "BTBaseAuth";
        public static readonly string VALID_ISSUER = "BTBaseAuth";
        public IConfiguration Configuration { get; private set; }
        public IServiceCollection ServiceCollection { get; private set; }
        public IApplicationBuilder ApplicationBuilder { get; set; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }


        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            this.ServiceCollection = services;
            services.AddMvc(ac => { })
            .AddJsonOptions(op =>
            {
                op.SerializerSettings.NullValueHandling = NullValueHandling.Ignore;
                op.SerializerSettings.Formatting = Formatting.None;
            });
            services.AddSingleton<AccountService>();
            services.AddSingleton<MemberService>();
            services.AddSingleton<SessionService>();
            services.AddDbContextPool<BTBaseDbContext>(builder =>
            {
                builder.UseMySQL(Environment.GetEnvironmentVariable("MYSQL_CONSTR"));
            });
            AddAuthentication(services);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            ApplicationBuilder = app;
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            TryConnectDB();
            app.UseAuthentication();
            app.UseMvc();
        }

        private void TryConnectDB()
        {
            using (var sc = ApplicationBuilder.ApplicationServices.CreateScope())
            {
                try
                {
                    var dbContext = sc.ServiceProvider.GetService<BTBaseDbContext>();
                    dbContext.Database.EnsureCreated();
                    Console.WriteLine("Connect DB Success");
                }
                catch (System.Exception ex)
                {
                    Console.WriteLine("Connect DB Error:" + ex.ToString());
                }
            }
        }

        private void AddAuthentication(IServiceCollection services)
        {
            services.AddAuthentication("Bearer").AddJwtBearer(jwtOptions =>
            {
                var securityKey = GetIssuerSigningKey(ApplicationBuilder.ApplicationServices);
                //var securityKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("a secret that needs to be at least 16 characters long"));
                jwtOptions.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = securityKey,
                    ValidateAudience = false, // All api service clients allow access
                    ValidAudience = SERVER_NAME,
                    ValidateIssuer = true,
                    ValidIssuer = VALID_ISSUER,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(5)
                };
            });
        }

        private SecurityKey GetIssuerSigningKey(IServiceProvider serviceProvider)
        {
            using (var sc = serviceProvider.CreateScope())
            {
                var dbContext = sc.ServiceProvider.GetService<BTBaseDbContext>();
                SecurityKeychain signingKey;
                try
                {
                    signingKey = dbContext.SecurityKeychain.First(x => x.Name == SERVER_NAME);
                }
                catch (System.InvalidOperationException)
                {
                    signingKey = new SecurityKeychain
                    {
                        Name = SERVER_NAME,
                        Note = "Use for issuer signing of BTBaseAuth"
                    };
                    signingKey.ResetNewRSAKeys();
                    var res = dbContext.SecurityKeychain.Add(signingKey);
                    signingKey = res.Entity;
                    dbContext.SaveChanges();
                }
                return new RsaSecurityKey(signingKey.ReadRSAParameters(true));
            }
        }
    }
}
