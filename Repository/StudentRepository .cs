using Dapper;
using MySqlConnector;
using StudentMs.Helper;
using StudentMs.Model;
using StudentMs.Repository.IRepository;
using System.Data;
using static StudentMs.Repository.StudentRepository;

namespace StudentMs.Repository
{
        public class StudentRepository : IRegisterRepository
        {
            private readonly string _connectionString;

            public StudentRepository(IConfiguration configuration)
            {
            _connectionString = configuration.GetConnectionString("DefaultConnection") ??  throw new ArgumentNullException(nameof(configuration));
        }

            public async Task<ApiResponse> RegisterStudentAsync(StudentRequest student)
            {
                using var con = new MySqlConnection(_connectionString);
            var hashedPassword = PasswordHelper.HashPassword(student.Password);
            var sp= "SaveStudent";
                var parameters = new DynamicParameters();
                parameters.Add("p_StudentName", student.StudentName, DbType.String);
                parameters.Add("p_StudentMail", student.StudentMail, DbType.String);
                parameters.Add("p_StudentPhoneNo", student.StudentPhoneNo, DbType.Int64);
                parameters.Add("p_Password", hashedPassword, DbType.String);
                parameters.Add("p_CollegeName", student.CollegeName, DbType.String);
                parameters.Add("p_StudentRollNo", student.StudentRollNo, DbType.String);
                parameters.Add("p_Department", student.Department, DbType.String);
                parameters.Add("p_Year", student.Year, DbType.Int32);
                parameters.Add("p_Degree", student.Degree, DbType.String);

                var result = await con.ExecuteAsync(sp, parameters, commandType: CommandType.StoredProcedure);

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