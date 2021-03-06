using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using BTBaseServices.DAL;
using BTBaseServices.Models;
using BTBaseServices.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using BTBaseServices;
using System.Security.Principal;

namespace BTBaseAuth.Controllers.v1
{
    [Route("api/v1/[controller]")]
    public class SessionsController : Controller
    {
        private readonly BTBaseDbContext dbContext;
        private readonly SessionService sessionService;
        private readonly AccountService accountService;
        private double SESSION_TOKEN_EXPIRY_MINUTES => double.Parse(Environment.GetEnvironmentVariable("SESSION_TOKEN_EXPIRY_MINUTES"));
        private double AUDIENCE_TOKEN_EXPIRY_MINUTES => double.Parse(Environment.GetEnvironmentVariable("AUDIENCE_TOKEN_EXPIRY_MINUTES"));

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
                    error = new ErrorResult { msg = "Device Is Logout", code = 404 }
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
                    var sessionTokenExpires = DateTime.Now.AddMinutes(SESSION_TOKEN_EXPIRY_MINUTES);
                    var sessionToken = CreateToken(Startup.ValidIssuer, Startup.AppName, sessionTokenExpires);
                    var audienceTokenExpires = DateTime.Now.AddMinutes(AUDIENCE_TOKEN_EXPIRY_MINUTES);
                    var audienceToken = CreateToken(Startup.ValidIssuer, audience, audienceTokenExpires);
                    return new ApiResult
                    {
                        code = this.SetResponseOK(),
                        content = new
                        {
                            AccountId = account.AccountId,
                            Session = session.SessionKey,
                            Token = audienceToken,
                            TokenExpires = (long)BahamutCommon.Utils.DateTimeUtil.UnixTimeSpanOfDateTime(audienceTokenExpires).TotalSeconds,
                            SessionToken = sessionToken,
                            SessionTokenExpires = (long)BahamutCommon.Utils.DateTimeUtil.UnixTimeSpanOfDateTime(sessionTokenExpires).TotalSeconds,
                            KickedDevices = logoutDevices
                        }
                    };
                }
                catch (System.Exception ex)
                {
                    return new ApiResult
                    {
                        code = this.SetResponseStatusCode(500),
                        error = new ErrorResult { msg = ex.Message, code = 500 }
                    };
                }
            }
            else
            {
                return new ApiResult
                {
                    code = this.SetResponseNotFound(),
                    error = new ErrorResult { code = 400, msg = "Validate Failed" }
                };
            }
        }

        [Authorize]
        [HttpPost("RefreshingToken")]
        public object RefreshToken(string audience)
        {
            try
            {
                if (sessionService.TestSession(dbContext, this.GetHeaderDeviceId(), this.GetHeaderAccountId(), this.GetHeaderSession(), false) == null)
                {
                    return new ApiResult
                    {
                        code = this.SetResponseForbidden(),
                        error = new ErrorResult { code = 404, msg = "Invalid Session" }
                    };
                }
                var expires = DateTime.Now.AddMinutes(AUDIENCE_TOKEN_EXPIRY_MINUTES);
                var token = CreateToken(Startup.ValidIssuer, audience, expires);
                return new ApiResult
                {
                    code = this.SetResponseOK(),
                    content = new
                    {
                        AccountId = this.GetHeaderAccountId(),
                        Token = token,
                        Expires = (long)BahamutCommon.Utils.DateTimeUtil.UnixTimeSpanOfDateTime(expires).TotalSeconds
                    }
                };
            }
            catch (System.Exception ex)
            {
                return new ApiResult
                {
                    code = this.SetResponseForbidden(),
                    error = new ErrorResult { code = 403, msg = ex.Message }
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

        private string CreateToken(string issuer, string audience, DateTime expireDate)
        {
            SecurityKeychain signingKey;
            if (string.IsNullOrWhiteSpace(audience))
            {
                throw new Exception("Null Audience Service");
            }

            var signingKeyName = Startup.GetAuthKeyName(audience);
            try
            {
                signingKey = dbContext.SecurityKeychain.First(x => x.Name == signingKeyName);
            }
            catch (System.Exception)
            {
                throw new Exception($"No Security Key Of Audience:{audience}");
            }

            string algorithm = null;
            switch (signingKey.Algorithm)
            {
                case SecurityKeychainRSAExtensions.ALGORITHM_RSA: algorithm = SecurityAlgorithms.RsaSha256Signature; break;
                case SecurityKeychainSymmetricsExtensions.ALGORITHM_SYMMETRIC: algorithm = SecurityAlgorithms.HmacSha256; break;
                default: throw new Exception($"Unsupport Audience Security Key Algorithm:{signingKey.Algorithm}");
            }

            var signingCredentials = new SigningCredentials(signingKey.GetSecurityKeys(true), algorithm);

            var handler = new JwtSecurityTokenHandler();
            return handler.CreateEncodedJwt(new SecurityTokenDescriptor
            {
                Issuer = Startup.ValidIssuer,
                Audience = audience,
                SigningCredentials = signingCredentials,
                Expires = expireDate
            });
        }
    }
}