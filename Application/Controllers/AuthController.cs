using Azure.Core;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Application.Controllers
{
    public class AuthController : BaseController
    {
        private readonly IConfiguration _configuration;
        private static readonly Dictionary<string, string> RefreshTokens = new();

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [AllowAnonymous]
        [HttpPost("v1/login")]
        public IActionResult Login([FromBody] LoginRequest loginRequest)
        {
            if (loginRequest.Username == "admin" && loginRequest.Password == "admin")
            {
                var token = GenerateJwtToken("adminUserId", "Admin", true);
                return Ok(token);
            }

            return Unauthorized("Invalid username or password.");
        }

        [Authorize]
        [HttpPost("v1/refresh-token")]
        public IActionResult RefreshToken([FromBody] RefreshRequest refreshRequest)
        {
            var principal = ValidateRefreshToken(refreshRequest.RefreshToken);
            if (principal == null)
            {
                return Unauthorized("Invalid refresh token.");
            }

            var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var newAccessToken = GenerateJwtToken(userId, "User");

            return Ok(new { token = newAccessToken });
        }

        private IDictionary<string, string> GenerateJwtToken(string userId, string role, bool includeRefreshToken = false)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Secret"]);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, userId),
                new Claim(ClaimTypes.Role, role),
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(1), 
                Issuer = _configuration["Jwt:Authority"],
                Audience = _configuration["Jwt:Audience"],
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var accessToken = tokenHandler.CreateToken(tokenDescriptor);
            var token = tokenHandler.WriteToken(accessToken);

            var response = new Dictionary<string, string>
            {
                { "token", token }
            };

            if (includeRefreshToken)
            {
                var refreshToken = GenerateRefreshToken(userId);
                SaveRefreshToken(userId, refreshToken);
                response.Add("refreshToken", refreshToken);
            }

            return response;
        }

        private string GenerateRefreshToken(string userId)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Secret"]);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.NameIdentifier, userId) }),
                Expires = DateTime.UtcNow.AddDays(30), 
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);

        }
        private void SaveRefreshToken(string userId, string refreshToken)
        {
            RefreshTokens[userId] = refreshToken;
        }

        private ClaimsPrincipal ValidateRefreshToken(string refreshToken)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_configuration["Jwt:Secret"]);

            try
            {
                var claimsPrincipal = tokenHandler.ValidateToken(refreshToken, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = false 
                }, out SecurityToken validatedToken);

                return claimsPrincipal;
            }
            catch (SecurityTokenException)
            {
                return null;
            }
        }
       

    }
}
public class LoginRequest
{
    public string Username { get; set; }
    public string Password { get; set; }
}
public class RefreshRequest
{
    public string RefreshToken { get; set; }
}