using AspNet7WebApiAuth.Core.DTOs;
using AspNet7WebApiAuth.Core.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace AspNet7WebApiAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        // Route for seeding my roles to database
        [HttpPost]
        [Route("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            var seedRoles = await _authService.SeedRoleAsync();
            return Ok(seedRoles);
        }

        // Route => Register
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDTO registerDto)
        {
            var registerResult = await _authService.RegisterAsync(registerDto);
            if(registerResult.isSuccess)
                return Ok(registerResult);

            return BadRequest(registerResult);
        }

        // Route => Login
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO loginDto)
        {
            var loginResult = await _authService.LoginAsync(loginDto);
            if (loginResult.isSuccess)
                return Ok(loginResult);

            return BadRequest(loginResult);
        }

        // Route => make user => admin
        [HttpPost]
        [Route("make-admin")]
        public async Task<IActionResult> MakeAdmin([FromBody] UpdatePermissionDTO updatePermissionDTO)
        {
            var operationResult = await _authService.MakeAdminAsync(updatePermissionDTO);

            if (operationResult.isSuccess)
            {
                return Ok(operationResult);
            }

            return BadRequest(operationResult);

        }

        // Route => make user => owner
        [HttpPost]
        [Route("make-owner")]
        public async Task<IActionResult> MakeOwner([FromBody] UpdatePermissionDTO updatePermissionDTO)
        {
            var operationResult = await _authService.MakeOwnerAsync(updatePermissionDTO);

            if (operationResult.isSuccess)
            {
                return Ok(operationResult);
            }

            return BadRequest(operationResult);

        }
    }
}
