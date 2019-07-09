using JWTwebAPI.Helper;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace JWTwebAPI.Controllers
{
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private readonly AppSettings _appSettings;

        
        public AuthController(IOptions<AppSettings> appSettings)
        {
            _appSettings = appSettings.Value;
        }

        [HttpPost("token")]
        public IActionResult Token()
        {
            
            var header = Request.Headers["Authorization"];
            if (header.ToString().StartsWith("Basic"))
            {
                var credValue = header.ToString().Substring("Basic ".Length).Trim();
                var usernameAndPassenc = Encoding.UTF8.GetString(Convert.FromBase64String(credValue));//admin:pass
                var usernameAndPass = usernameAndPassenc.Split(":");
                // Check in DB username and password exist
                string[] roles = {"Admin", "Editor"};
                IdentityOptions _options = new IdentityOptions();
                 
                var claims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(ClaimTypes.Sid, "1453"),
                    new Claim(ClaimTypes.Name, usernameAndPass[0]),
                    new Claim(ClaimTypes.NameIdentifier, usernameAndPass[0])

                };
                claims.AddRange(roles.Select(role => new Claim(ClaimsIdentity.DefaultRoleClaimType, role)));
                if (usernameAndPass[0] == "Admin" && usernameAndPass[1] == "pass")
                {
                   
                    var tokenHandler = new JwtSecurityTokenHandler();
                    var key = Encoding.ASCII.GetBytes(_appSettings.Secret);

                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = new ClaimsIdentity(claims),
                        Expires = DateTime.UtcNow.AddDays(7),
                        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                    };
                    var token = tokenHandler.CreateToken(tokenDescriptor);
                   
                    return Ok(new { Token = tokenHandler.WriteToken(token) });
                }
            }

            return BadRequest("wrong request");

        }
    }
}