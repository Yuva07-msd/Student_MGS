using Dapper;
using MySql.Data.MySqlClient;
using StudentMS.Model;
using StudentMS.Repository.IRepository;
using System.Data;

namespace StudentMS.Repository
{
    public class StudentRepository : IStudentRepository
    {
        private readonly string _connectionString;
        public StudentRepository(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection")
                ?? throw new ArgumentNullException(nameof(_connectionString), "Connection string is missing");
        }

        public async Task<ApiResponse> RegisterStudentAsync(StudentRequest student)
        {
            using var con = new MySqlConnection(_connectionString);

            var result = await con.ExecuteAsync(
                "SaveStudent",
                new
                {
                    p_StudentName = student.studentName,
                    p_StudentMail = student.studentEmail,
                    p_PasswordHash = student.PasswordHash,
                    p_CollegeName = student.CollegeName,
                    p_StudentRollNo = student.StudentRollNo,
                    p_Department = student.Department,
                    p_Year = student.Year,
                    p_Degree = student.Degree
                },
                commandType: CommandType.StoredProcedure
            );

            if (result > 0)
            {
                return new ApiResponse
                {
                    Status = true,
                    Message = "Student registered successfully"
                };
            }

            return new ApiResponse
            {
                Status = false,
                Message = "Failed to register student"
            };

        }
    }
}
