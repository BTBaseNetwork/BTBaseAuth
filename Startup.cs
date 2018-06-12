using System;
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
        public static readonly string AppName = "BTBaseAuth";
        public static readonly string ValidIssuer = "BTBaseAuth";
        public static string GetAuthKeyName(string audience) => $"auth_key_{audience.ToLower()}";
        public static readonly string AppAuthKeyName = GetAuthKeyName(AppName);

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
            TryConnectDB(env.IsDevelopment());
            TryCreateAudienceKey(app.ApplicationServices);
            app.UseAuthentication();
            app.UseMvc();
        }

        private void TryCreateAudienceKey(IServiceProvider serviceProvider)
        {
            var key = GetIssuerSigningKey(serviceProvider);
            Console.WriteLine("Audience Key:" + key.Name);
        }

        private void TryConnectDB(bool isDevelopment)
        {
            using (var sc = ApplicationBuilder.ApplicationServices.CreateScope())
            {
                try
                {
                    var dbContext = sc.ServiceProvider.GetService<BTBaseDbContext>();
                    if (isDevelopment)
                    {
                        dbContext.Database.EnsureCreated();
                    }
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
                jwtOptions.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = securityKey.GetSecurityKeys(false),
                    ValidateAudience = true,
                    ValidAudience = AppName,
                    ValidateIssuer = true,
                    ValidIssuer = ValidIssuer,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(5)
                };
            });
        }

        private SecurityKeychain GetIssuerSigningKey(IServiceProvider serviceProvider)
        {
            using (var sc = serviceProvider.CreateScope())
            {
                var dbContext = sc.ServiceProvider.GetService<BTBaseDbContext>();
                SecurityKeychain signingKey;
                try
                {
                    signingKey = dbContext.SecurityKeychain.FirstOrDefault(x => x.Name == AppAuthKeyName);
                    if (signingKey == null || string.IsNullOrWhiteSpace(signingKey.Name))
                    {
                        Console.WriteLine("No Signing Key, Creating One...");
                        throw new System.InvalidOperationException("No Signing Key");
                    }
                }
                catch (System.InvalidOperationException)
                {
                    var note = $"Authentication key for the audience service:{AppName}";
                    signingKey = SecurityKeychainProvider.Create(AppAuthKeyName, SecurityKeychainSymmetricsExtensions.ALGORITHM_SYMMETRIC, note);
                    var res = dbContext.SecurityKeychain.Add(signingKey);
                    signingKey = res.Entity;
                    dbContext.SaveChanges();
                    Console.WriteLine("Signing Key Created:" + signingKey.Name);
                }
                return signingKey;
            }
        }
    }
}
