using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuthExample
{
    public class JwtAuthenticationManager
    {
        public JwtAuthResponse Authenticate(string userName, string password)
        {
            //Validating User Name and Password
            if(userName != "user01" || password != "password123")
            {
                return null;
            }

            var tokenExpireTimeStamp = DateTime.UtcNow.AddMinutes(Constants.JWT_TOKEN_VALIDITY_MINS);
            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var tokenKey = Encoding.ASCII.GetBytes(Constants.JWT_SECURITY_KEY);
            var securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new List<Claim>
                {
                    new Claim("username", userName),
                    new Claim(ClaimTypes.PrimaryGroupSid, "User Group 01")
                }),
                Expires = tokenExpireTimeStamp,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature)
            };

            var securityToken = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
            var token = jwtSecurityTokenHandler.WriteToken(securityToken);

            return new JwtAuthResponse
            {
                token = token,
                user_name = userName,
                expires_in = (int)tokenExpireTimeStamp.Subtract(DateTime.Now).TotalSeconds,
            };
        }
    }
}
