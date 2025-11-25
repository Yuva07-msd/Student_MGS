using Microsoft.AspNetCore.Mvc;
using StudentMs.Model;
using StudentMs.Repository.IRepository;

namespace StudentMs.Controllers
{
 
        [Route("api/[controller]")]
        [ApiController]
        public class ARegController : ControllerBase
        {
            private readonly IRegisterRepository _studentRepository;
            public ARegController(IRegisterRepository studentRepository)
            {
                _studentRepository = studentRepository;
            }
            [HttpPost("register")]
            public async Task<IActionResult> RegisterStudent([FromBody] StudentRequest studentRequest)
            {
                var response = await _studentRepository.RegisterStudentAsync(studentRequest);
                if (response.Status)
                {
                    return Ok(response);
                }
                return BadRequest(response);
            }
        }

}
