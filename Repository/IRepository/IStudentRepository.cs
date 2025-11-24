using StudentMS.Model;

namespace StudentMS.Repository.IRepository
{
    public interface IStudentRepository
    {
            Task<ApiResponse> RegisterStudentAsync(StudentRequest student);

    }
}
