using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BTBaseServices;
using BTBaseServices.DAL;
using BTBaseServices.Models;
using BTBaseServices.Services;
using JwtUtils;
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

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IApplicationBuilder app, IServiceCollection services)
        {
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

            AddAuthentication(app, services);
        }



        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            TryConnectDB(app);
            app.UseMvc();
        }

        private void TryConnectDB(IApplicationBuilder app)
        {
            using (var sc = app.ApplicationServices.CreateScope())
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

        private void AddAuthentication(IApplicationBuilder app, IServiceCollection services)
        {
            BTWebServerAuthKey authKey;
            var securityKey = GetAuthenticationKey(app.ApplicationServices, out authKey);
            services.AddAuthentication().AddJwtBearer(jwtOptions =>
            {
                jwtOptions.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = securityKey,
                    ValidateAudience = false, // All audience clients can access this auth server
                    ValidateIssuer = true,
                    ValidIssuer = SERVER_NAME,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(5)
                };
            });
        }

        private SecurityKey GetAuthenticationKey(IServiceProvider serviceProvider, out BTWebServerAuthKey authKey)
        {
            using (var sc = serviceProvider.CreateScope())
            {
                var dbContext = sc.ServiceProvider.GetService<BTBaseDbContext>();
                try
                {
                    authKey = dbContext.BTWebServerAuthKey.First(x => x.ServerName == SERVER_NAME);
                    return ServerAuthKeyUtils.ConvertToKey<SecurityKey>(authKey);
                }
                catch (System.InvalidOperationException)
                {
                    var skey = ServerAuthKeyUtils.CreateNewSecurityKey<SecurityKey>(ServerAuthKeyUtils.ALGORITHM_RSA);
                    var res = dbContext.BTWebServerAuthKey.Add(ServerAuthKeyUtils.GenerateAuthKey(SERVER_NAME, skey));
                    authKey = res.Entity;
                    return skey;
                }
            }
        }
    }
}
