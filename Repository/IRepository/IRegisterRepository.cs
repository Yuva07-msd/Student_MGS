using StudentMs.Model;

namespace StudentMs.Repository.IRepository
{
    public interface IRegisterRepository
    {
        public Task<ApiResponse> RegisterStudentAsync(StudentRequest student);
    }
}
