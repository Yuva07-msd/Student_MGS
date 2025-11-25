
using StudentMs.Model;

namespace StudentMs.Repository.IRepository
{
    public interface IAuthRepository
    {
        public Task<LoginResult> LoginStudentAsync(string studentMail, string password);
        LoginResponse GenerateJwtToken(User user);
    }
}
