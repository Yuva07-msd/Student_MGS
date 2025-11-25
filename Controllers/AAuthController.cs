using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using StudentMs.Model;
using StudentMs.Repository.IRepository;

namespace StudentMs.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AAuthController : ControllerBase
    {
        private readonly IAuthRepository _authRepository;

        public AAuthController(IAuthRepository authRepository)
        {
            _authRepository = authRepository;
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (string.IsNullOrEmpty(request.StudentMail))
            {
                return BadRequest("StudentMail is required.");
            }
            if (string.IsNullOrEmpty(request.Password))
            {
                return BadRequest("Password is required.");
            }
           
            var loginresult = await _authRepository.LoginStudentAsync(request.StudentMail, request.Password);
            if (loginresult == null || loginresult.User == null)
            {
                return Unauthorized("Invalid credentials.");
            }
            var tokenResponse = _authRepository.GenerateJwtToken(loginresult.User);
            return Ok(new
            {
                UserDetails = tokenResponse,
                Messages = loginresult.Messages
            });
 
        }
    }
}
