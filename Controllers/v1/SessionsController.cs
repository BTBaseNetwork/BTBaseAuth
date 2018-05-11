using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using BTBaseServices.DAL;
using BTBaseServices.Models;
using BTBaseServices.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using BTBaseServices;

namespace BTBaseAuth.Controllers.v1
{
    [Route("api/v1/[controller]")]
    public class SessionsController : Controller
    {
        private readonly BTBaseDbContext dbContext;
        private readonly SessionService sessionService;
        private readonly AccountService accountService;
        private readonly double TOKEN_EXPIRED_DAYS = 60;

        public SessionsController(BTBaseDbContext dbContext, SessionService sessionService, AccountService accountService)
        {
            this.dbContext = dbContext;
            this.sessionService = sessionService;
            this.accountService = accountService;
        }

        [HttpGet("DeviceAccount")]
        public object GetDeviceAccountInfo(bool active = false)
        {
            var session = active ?
            sessionService.ReactiveSession(dbContext, this.GetHeaderDeviceId()) :
            sessionService.GetSession(dbContext, this.GetHeaderDeviceId());

            if (session == null)
            {
                return new ApiResult
                {
                    code = this.SetResponseNotFound(),
                    msg = "Device Is Logout"
                };
            }
            else
            {
                var account = accountService.GetProfile(dbContext, session.AccountId);
                return new ApiResult
                {
                    code = this.SetResponseOK(),
                    content = new { AccountId = account.AccountId, UserName = account.UserName, Nick = account.Nick }
                };
            }
        }

        [HttpPost]
        public object Login(string userstring, string password, string audience)
        {

            var account = accountService.ValidateProfile(dbContext, userstring, password);

            if (account != null)
            {
                var session = sessionService.GetSession(dbContext, this.GetHeaderDeviceId(), account.AccountId, true);
                if (session == null)
                {
                    session = sessionService.NewSession(dbContext, new BTDeviceSession
                    {
                        AccountId = account.AccountId,
                        DeviceId = this.GetHeaderDeviceId(),
                        DeviceName = this.GetHeaderDeviceName()
                    });
                }
                var logoutDevices = sessionService.InvalidSessionAccountLimited(dbContext, account.AccountId, 5);
                try
                {
                    var token = CreateToken(session.DeviceId, audience, this.GetHeaderClientId(), account.AccountId, session.SessionKey, DateTime.Now.AddDays(TOKEN_EXPIRED_DAYS));
                    return new ApiResult
                    {
                        code = this.SetResponseOK(),
                        content = new
                        {
                            AccountId = account.AccountId,
                            Session = session.SessionKey,
                            Token = token,
                            KickedDevices = logoutDevices
                        }
                    };
                }
                catch (System.Exception ex)
                {
                    return new ApiResult
                    {
                        code = this.SetResponseStatusCode(400),
                        error = new ErrorResult { msg = ex.Message, code = 400 }
                    };
                }
            }
            else
            {
                return new ApiResult
                {
                    code = this.SetResponseNotFound(),
                    msg = "Validate Failed"
                };
            }
        }

        [Authorize]
        [HttpGet("RefreshedToken")]
        public object RefreshToken()
        {
            try
            {
                var audience = Request.HttpContext.User.Claims.First(c => c.Type == JwtRegisteredClaimNames.Aud).Value;
                var session = Request.HttpContext.User.Claims.First(c => c.Type == JwtRegisteredClaimNames.Sid).Value;
                var accountId = Request.HttpContext.User.Claims.First(c => c.Type == ClaimTypes.NameIdentifier).Value;
                var clientId = Request.HttpContext.User.Claims.First(c => c.Type == BTBaseServices.JWTClaimNames.ClientUniqueId).Value;
                var deviceId = Request.HttpContext.User.Claims.First(c => c.Type == BTBaseServices.JWTClaimNames.DeviceIdentifier).Value;
                var token = CreateToken(deviceId, audience, clientId, accountId, session, DateTime.Now.AddDays(TOKEN_EXPIRED_DAYS));
                return new ApiResult
                {
                    code = this.SetResponseOK(),
                    content = new
                    {
                        AccountId = accountId,
                        Token = token
                    }
                };
            }
            catch (System.Exception ex)
            {
                return new ApiResult
                {
                    code = this.SetResponseForbidden(),
                    error = new ErrorResult { code = 404, msg = ex.Message }
                };
            }
        }

        [Authorize]
        [HttpDelete]
        public object Logout()
        {
            var cnt = sessionService.InvalidAllSession(dbContext, this.GetHeaderAccountId(), this.GetHeaderDeviceId(), this.GetHeaderSession()).Count();
            return new ApiResult
            {
                code = cnt > 0 ? this.SetResponseOK() : this.SetResponseNotFound(),
                msg = "Devices Session Invalided:" + cnt,
                content = cnt
            };
        }

        private string CreateToken(string deviceId, string audience, string clientId, string accountId, string session, DateTime expireDate)
        {
            SecurityKeychain signingKey;
            try
            {
                signingKey = dbContext.SecurityKeychain.First(x => x.Name == Startup.SERVER_NAME);
            }
            catch (System.Exception)
            {
                throw new Exception("No Audience Service");
            }

            var secretKey = new RsaSecurityKey(signingKey.ReadRSAParameters(true));
            //var secretKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("a secret that needs to be at least 16 characters long"));
            var notBefore = DateTime.Now;
            var claims = new List<Claim>();
            try
            {
                var claimsArr = new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, accountId),
                    new Claim(BTBaseServices.JWTClaimNames.DeviceIdentifier, deviceId),
                    new Claim(BTBaseServices.JWTClaimNames.ClientUniqueId,clientId),
                    new Claim(JwtRegisteredClaimNames.Aud, audience),
                    new Claim(JwtRegisteredClaimNames.Sid, session)
                };
                claims.AddRange(claims);
            }
            catch (System.Exception)
            {
                throw new Exception("Token Claim Parameters Error");
            }

            var token = new JwtSecurityToken(
                issuer: Startup.VALID_ISSUER,
                audience: audience,
                claims: claims,
                notBefore: notBefore,
                expires: expireDate,
                //signingCredentials: new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256)
                signingCredentials: new SigningCredentials(secretKey, SecurityAlgorithms.RsaSha256Signature)
            );

            string jwtToken = new JwtSecurityTokenHandler().WriteToken(token);
            return jwtToken;
        }
    }
}