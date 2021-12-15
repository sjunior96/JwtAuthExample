using JwtAuthExample.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthExample.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [AllowAnonymous]
    public class AccountController : ControllerBase
    {
        [HttpPost]
        [Route("Login")]
        public IActionResult Login([FromForm]AuthenticationRequest authenticationRequest)
        {
            var jwtAuthenticationManager = new JwtAuthenticationManager();
            var authResult = jwtAuthenticationManager.Authenticate(authenticationRequest.UserName, authenticationRequest.Password);
            
            if(authResult == null)
            {
                return Unauthorized();
            }
            return Ok(authResult);
        }
    }
}
