using System.Data;
using Dapper;
using MySqlConnector;
using StudentMs.Model;
using StudentMs.Repository.IRepository;

namespace StudentMs.Repository
{
    public class StudentRepository : IRegisterRepository
    {
        private readonly string _connectionString =
            "Server=localhost;Database=student_management_system;User=root;Password=root;";

        public async Task<ApiResponse> RegisterStudentAsync(StudentRequest student)
        {
            await using var conn = new MySqlConnection(_connectionString);
            await conn.OpenAsync();


            var parameters = new DynamicParameters();
            parameters.Add("StudentName", student.StudentName, DbType.String);
            parameters.Add("StudentMail", student.StudentMail, DbType.String);
            parameters.Add("StudentPhoneNo", student.StudentPhoneNo, DbType.String);
            string hashedPassword = BCrypt.Net.BCrypt.HashPassword(student.Password);
            parameters.Add("PasswordHash",hashedPassword, DbType.String); // hash before storing if needed
            parameters.Add("CollegeName", student.CollegeName, DbType.String);
            parameters.Add("StudentRollNo", student.StudentRollNo, DbType.String);
            parameters.Add("Depertment", student.Department, DbType.String); // match SP field
            parameters.Add("Year", student.Year, DbType.Int32);
            parameters.Add("Degree", student.Degree, DbType.String);

            // Use CommandType.StoredProcedure
            var result = await conn.QueryFirstOrDefaultAsync<int>(
                "SaveStudent",
                parameters,
                commandType: CommandType.StoredProcedure
            );

            if (result == -1)
            {
                return new ApiResponse
                {
                    Status = false,
                    Message = "Email already exists."
                };
            }

            if (result > 0)
            {
                return new ApiResponse
                {
                    Status = true,
                    Message = "Student registered successfully."
                };
            }

            return new ApiResponse
            {
                Status = false,
                Message = "Failed to register student."
            };
        }
    }
}
