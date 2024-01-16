using System;
using System.Collections.Generic;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using UI.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;

namespace UI.Controllers
{
    [Authorize]
    public class CustomersController : Controller
    {
        
            private readonly IConfiguration _configuration;

            public CustomersController(IConfiguration configuration)
            {
                this._configuration = configuration;
            }
        public async Task<IActionResult> LogOut()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Login", "Access");
        }

        //private bool IsValidUser(string userName, string password)
        //{
        //    using (SqlConnection sqlConnection = new SqlConnection(_configuration.GetConnectionString("DevConnection")))
        //    {
        //        sqlConnection.Open();
        //        using (SqlCommand cmd = new SqlCommand("ValidateUser", sqlConnection))
        //        {
        //            cmd.CommandType = CommandType.StoredProcedure;
        //            cmd.Parameters.AddWithValue("@UserName", userName);
        //            cmd.Parameters.AddWithValue("@Password", HashPassword(password));

        //            var result = cmd.ExecuteScalar();
        //            return result != null && (int)result > 0; // Assuming the stored procedure returns a count or some indication of validity
        //        }
        //    }
        //}

        //[HttpPost]
        //public IActionResult Login([FromBody] LoginRequestModel model)
        //{
        //    if (IsValidUser(model.UserName, model.Password))
        //    {
        //        var token = GenerateJwtToken(model.UserName);
        //        return Ok(new { Token = token });
        //    }

        //    return Unauthorized();
        //}

        //[Authorize]
        //[HttpPost]
        //public IActionResult Logout()
        //{
        //    var userId = GetUserIdFromClaim();
        //    if (userId.HasValue)
        //    {
        //        InvalidateToken(userId.Value);
        //        return Ok(new { Message = "Logout successful" });
        //    }

        //    return Unauthorized();
        //}

        //private void InvalidateToken(int userId)
        //{
        //    using (SqlConnection sqlConnection = new SqlConnection(_configuration.GetConnectionString("DevConnection")))
        //    {
        //        sqlConnection.Open();
        //        using (SqlCommand cmd = new SqlCommand("InvalidateToken", sqlConnection))
        //        {
        //            cmd.CommandType = CommandType.StoredProcedure;
        //            cmd.Parameters.AddWithValue("@UserId", userId);
        //            cmd.ExecuteNonQuery();
        //        }
        //    }
        //}

        //// Other helper methods remain the same...


        //[HttpPost]
        //public IActionResult Post(Users _userData)
        //{
        //    if (_userData != null && _userData.UserName != null && _userData.Password != null)
        //    {
        //        var user = GetUser(_userData.UserName, _userData.Password);
        //        if (user != null)
        //        {
        //            var claims = new[]
        //            {
        //        new Claim(JwtRegisteredClaimNames.Sub, _configuration["Jwt:Subject"]),
        //        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        //        new Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToString()),
        //        new Claim("UserId", user.UserId.ToString()),
        //        new Claim("UserName", user.UserName)
        //    };

        //            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
        //            var signIn = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        //            var token = new JwtSecurityToken(_configuration["Jwt:Issuer"],
        //                _configuration["Jwt:Audience"],
        //                claims, expires: DateTime.UtcNow.AddDays(1),
        //                signingCredentials: signIn);

        //            return Ok(new JwtSecurityTokenHandler().WriteToken(token));
        //        }
        //        else
        //        {
        //            return BadRequest("Invalid credentials");
        //        }
        //    }
        //    else
        //    {
        //        return BadRequest();
        //    }
        //}
        ////Get : login
        //private Users GetUser(string userName, string password)
        //{
        //    // Replace "YourConnectionString" with your actual connection string
        //    using (SqlConnection connection = new SqlConnection("DevConnection"))
        //    {
        //        connection.OpenAsync();

        //        using (SqlCommand command = new SqlCommand("ValidateUser", connection))
        //        {
        //            command.CommandType = CommandType.StoredProcedure;

        //            // Add parameters to the stored procedure
        //            command.Parameters.AddWithValue("@UserName", userName);
        //            command.Parameters.AddWithValue("@Password", password);

        //            using (SqlDataReader reader = command.ExecuteReader())
        //            {
        //                if (reader.Read())
        //                {
        //                    // Map the database columns to the Users object
        //                    return new Users
        //                    {
        //                        UserId = Convert.ToInt32(reader["UserId"]),
        //                        UserName = reader["UserName"].ToString(),
        //                        // Map other properties as needed
        //                    };
        //                }
        //            }
        //        }
        //    }

        //    return null;
        //}
        //    private string GenerateJwtToken(int userId, string userName)
        //    {
        //        var claims = new[]
        //        {
        //    new Claim(JwtRegisteredClaimNames.Sub, _configuration["Jwt:Subject"]),
        //    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        //    new Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToString()),
        //    new Claim("UserId", userId.ToString()),
        //    new Claim("UserName", userName)
        //};

        //        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
        //        var signIn = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        //        var token = new JwtSecurityToken(_configuration["Jwt:Issuer"],
        //            _configuration["Jwt:Audience"],
        //            claims, expires: DateTime.UtcNow.AddDays(1),
        //            signingCredentials: signIn);

        //        return new JwtSecurityTokenHandler().WriteToken(token);
        //    }

        //    private bool IsValidUser(string userName, string password)
        //    {
        //        using (SqlConnection sqlConnection = new SqlConnection(_configuration.GetConnectionString("DevConnection")))
        //        {
        //            sqlConnection.Open();
        //            using (SqlCommand cmd = new SqlCommand("ValidateUser", sqlConnection))
        //            {
        //                cmd.CommandType = CommandType.StoredProcedure;
        //                cmd.Parameters.AddWithValue("@UserName", userName);
        //                cmd.Parameters.AddWithValue("@Password", HashPassword(password));

        //                var result = cmd.ExecuteScalar();
        //                return result != null && (int)result > 0; // Assuming the stored procedure returns a count or some indication of validity
        //            }
        //        }
        //    }

        //    [HttpPost]
        //    public IActionResult Login([FromBody] Users model)
        //    {
        //        if (IsValidUser(model.UserName, model.Password))
        //        {
        //            var user = GetUser(model.UserName, model.Password);

        //            if (user != null)
        //            {
        //                var token = GenerateJwtToken(user.UserId, user.UserName);
        //                return Ok(new { Token = token });
        //            }
        //            else
        //            {
        //                return BadRequest("Invalid credentials");
        //            }
        //        }

        //        return Unauthorized();
        //    }

        //    [Authorize]
        //    [HttpPost]
        //    public IActionResult Logout()
        //    {
        //        var userId = GetUserIdFromClaim();
        //        if (userId.HasValue)
        //        {
        //            InvalidateToken(userId.Value);
        //            return Ok(new { Message = "Logout successful" });
        //        }

        //        return Unauthorized();
        //    }

        //    private void InvalidateToken(int userId)
        //    {
        //        using (SqlConnection sqlConnection = new SqlConnection(_configuration.GetConnectionString("DevConnection")))
        //        {
        //            sqlConnection.Open();
        //            using (SqlCommand cmd = new SqlCommand("InvalidateToken", sqlConnection))
        //            {
        //                cmd.CommandType = CommandType.StoredProcedure;
        //                cmd.Parameters.AddWithValue("@UserId", userId);
        //                cmd.ExecuteNonQuery();
        //            }
        //        }
        //    }

        //    [HttpPost]
        //    public IActionResult Post(Users _userData)
        //    {
        //        if (_userData != null && !string.IsNullOrEmpty(_userData.UserName) && !string.IsNullOrEmpty(_userData.Password))
        //        {
        //            var user = GetUser(_userData.UserName, _userData.Password);
        //            if (user != null)
        //            {
        //                var token = GenerateJwtToken(user.UserId, user.UserName);
        //                return Ok(new { Token = token });
        //            }
        //            else
        //            {
        //                return BadRequest("Invalid credentials");
        //            }
        //        }
        //        else
        //        {
        //            return BadRequest();
        //        }
        //    }

        //    private Users GetUser(string userName, string password)
        //    {
        //        using (SqlConnection connection = new SqlConnection(_configuration.GetConnectionString("DevConnection")))
        //        {
        //            connection.Open();
        //            using (SqlCommand command = new SqlCommand("ValidateUser", connection))
        //            {
        //                command.CommandType = CommandType.StoredProcedure;
        //                command.Parameters.AddWithValue("@UserName", userName);
        //                command.Parameters.AddWithValue("@Password", HashPassword(password));

        //                using (SqlDataReader reader = command.ExecuteReader())
        //                {
        //                    if (reader.Read())
        //                    {
        //                        return new Users
        //                        {
        //                            UserId = Convert.ToInt32(reader["UserId"]),
        //                            UserName = reader["UserName"].ToString(),
        //                            // Map other properties as needed
        //                        };
        //                    }
        //                }
        //            }
        //        }

        //        return null;
        //    }

        // Other helper methods remain the same...


        // Helper method to hash the password (use a more secure hashing algorithm in production)






        //public IActionResult Login()
        //{
        //    ClaimsPrincipal claimsPrincipal = HttpContext.User;
        //    if (claimsPrincipal.Identity.IsAuthenticated)
        //    {
        //        return RedirectToAction("Index", "Home");
        //    }
        //    return View();
        //}

        //[HttpPost]
        //public async Task<IActionResult> Login(Users userlogin)
        //{
        //    if (IsValidUser(userlogin.Email, userlogin.Password))
        //    {
        //        List<Claim> claims = new List<Claim>()
        //        {
        //            new Claim(ClaimTypes.NameIdentifier, userlogin.Email),
        //            new Claim("otherproperties", "Example Role")
        //        };

        //        ClaimsIdentity identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

        //        AuthenticationProperties pr = new AuthenticationProperties()
        //        {
        //            AllowRefresh = true,
        //            IsPersistent = userlogin.KeepLoggedIn
        //        };

        //        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity), pr);
        //        return RedirectToAction("Index", "Home");
        //    }

        //    ViewData["ValidateMessage"] = "User not found";
        //    return View();
        //}

        //private bool IsValidUser(string email, string password)
        //{
        //    using (SqlConnection sqlConnection = new SqlConnection(_configuration.GetConnectionString("DevConnection")))
        //    {
        //        sqlConnection.Open();
        //        using (SqlCommand cmd = new SqlCommand("ValidateUser", sqlConnection))
        //        {
        //            cmd.CommandType = System.Data.CommandType.StoredProcedure;
        //            cmd.Parameters.AddWithValue("@Email", email);
        //            cmd.Parameters.AddWithValue("@Password", password);

        //            var result = cmd.ExecuteScalar();
        //            return result != null && (int)result > 0; // Assuming the stored procedure returns a count or some indication of validity
        //        }
        //    }
        //}

















        //----------------------communicationHistory-----------------------------------//
        public IActionResult CommunicationHistory(int id)
        {
            var communications = GetCommunicationHistory(id);
            return View(communications);
        }

        [HttpGet]
        public IActionResult AddCommunication(int id)
        {
            ViewData["CustomerId"] = id;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult AddCommunication([Bind("CustomerId,CommunicationType,CommunicationDetails")] CommunicationHistory communication)
        {
            if (ModelState.IsValid)
            {
                communication.CommunicationDate = DateTime.Now;
                AddCommunicationEntry(communication);
                return RedirectToAction("CommunicationHistory", new { id = communication.CustomerId });
            }

            return View(communication);
        }

        private List<CommunicationHistory> GetCommunicationHistory(int CustomerId)
        {
            var communications = new List<CommunicationHistory>();

            using (var sqlConnection = new SqlConnection(_configuration.GetConnectionString("DevConnection")))
            {
                sqlConnection.Open();

                using (var cmd = new SqlCommand("GetCommunicationHistory", sqlConnection))
                {
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.AddWithValue("@CustomerId", CustomerId);

                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            var communication = new CommunicationHistory
                            {
                                CommunicationId = Convert.ToInt32(reader["CommunicationId"]),
                                CustomerId = Convert.ToInt32(reader["CustomerId"]),
                                CommunicationDate = Convert.ToDateTime(reader["CommunicationDate"]),
                                CommunicationType = reader["CommunicationType"].ToString(),
                                CommunicationDetails = reader["CommunicationDetails"].ToString()
                            };

                            communications.Add(communication);
                        }
                    }
                }
            }

            return communications;
        }

        private void AddCommunicationEntry(CommunicationHistory communication)
        {
            using (var sqlConnection = new SqlConnection(_configuration.GetConnectionString("DevConnection")))
            {
                sqlConnection.Open();

                using (var cmd = new SqlCommand("AddCommunicationEntry", sqlConnection))
                {
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.AddWithValue("@CustomerId", communication.CustomerId);
                    cmd.Parameters.AddWithValue("@CommunicationDate", communication.CommunicationDate);
                    cmd.Parameters.AddWithValue("@CommunicationType", communication.CommunicationType);
                    cmd.Parameters.AddWithValue("@CommunicationDetails", communication.CommunicationDetails);

                    cmd.ExecuteNonQuery();
                }
            }
        }






        // GET: Customers
        public IActionResult Index()
            {
                DataTable dataTable = new DataTable();
                using (SqlConnection sqlConnection = new SqlConnection(_configuration.GetConnectionString("DevConnection")))
                {
                    sqlConnection.Open();
                    SqlDataAdapter cmd = new SqlDataAdapter("Customer_List", sqlConnection);
                    cmd.SelectCommand.CommandType = CommandType.StoredProcedure;
                    cmd.Fill(dataTable);

                }
                return View(dataTable);
            }




            // GET: Customers/CreateOrEdit/
            public IActionResult CreateOrEdit(int? id)
            {

                Customer customer = new Customer();
                if (id > 0)
                    customer = GetCustomerById(id);
                return View(customer);
            }

        // POST: Customers/CreateOrEdit/

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult CreateOrEdit(int id, [Bind("CustomerId,FirstName,LastName,Email,PhoneNumber")] Customer customer)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    using (SqlConnection sqlConnection = new SqlConnection(_configuration.GetConnectionString("DevConnection")))
                    {
                        sqlConnection.Open();

                        using (SqlCommand cmd = new SqlCommand("CustomerCreateOrEdit", sqlConnection))
                        {
                            cmd.CommandType = CommandType.StoredProcedure;
                            cmd.Parameters.AddWithValue("CustomerId", customer.CustomerId);
                            cmd.Parameters.AddWithValue("FirstName", customer.FirstName);
                            cmd.Parameters.AddWithValue("LastName", customer.LastName);
                            cmd.Parameters.AddWithValue("Email", customer.Email);
                            cmd.Parameters.AddWithValue("PhoneNumber", customer.PhoneNumber);

                            SqlParameter errorCodeParam = new SqlParameter("@errorcode", SqlDbType.Int);
                            errorCodeParam.Direction = ParameterDirection.Output;
                            cmd.Parameters.Add(errorCodeParam);

                            cmd.ExecuteNonQuery();

                            int errorCode = Convert.ToInt32(cmd.Parameters["@errorcode"].Value);

                            if (errorCode == 200)
                            {
                                return RedirectToAction(nameof(Index));
                            }
                            else if(errorCode == 201)
                            {
                                return RedirectToAction(nameof(Index));
                            }
                            else if (errorCode == 400)
                            {
                                ModelState.AddModelError(string.Empty, "Email or phone number already exists.");
                            }
                            else
                            {
                                ModelState.AddModelError(string.Empty, "Error occurred during operation. Please try again.");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    // Log the exception for further analysis
                    ModelState.AddModelError(string.Empty, "Error occurred during operation. Please try again.");
                }
            }

            return View(customer);
        }


        // GET: Customers/Delete/5
        public IActionResult Delete(int? id)
            {
                Customer customer = GetCustomerById(id);
                return View(customer);
            }
            // POST: Customers/Delete/5
            [HttpPost, ActionName("Delete")]
            [ValidateAntiForgeryToken]
            public IActionResult DeleteConfirmed(int id)
            {
                using (SqlConnection sqlConnection = new SqlConnection(_configuration.GetConnectionString("DevConnection")))
                {
                    sqlConnection.Open();
                    SqlCommand cmd = new SqlCommand("CustomerDeleteById", sqlConnection);
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.AddWithValue("CustomerId", id);
                    cmd.ExecuteNonQuery();

                }
                return RedirectToAction(nameof(Index));
            }

            //nonAction only getting the data
            public Customer GetCustomerById(int? id)
            {
                Customer customer = new Customer();
                using (SqlConnection sqlConnection = new SqlConnection(_configuration.GetConnectionString("DevConnection")))
                {
                    DataTable dataTable = new DataTable();
                    sqlConnection.Open();
                    SqlDataAdapter cmd = new SqlDataAdapter("CustomerViewById", sqlConnection);
                    cmd.SelectCommand.CommandType = CommandType.StoredProcedure;
                    cmd.SelectCommand.Parameters.AddWithValue("CustomerId", id);
                    cmd.Fill(dataTable);

                    if (dataTable.Rows.Count == 1)
                    {
                        customer.CustomerId = Convert.ToInt32(dataTable.Rows[0]["CustomerId"].ToString());
                        customer.FirstName = dataTable.Rows[0]["FirstName"].ToString();
                        customer.LastName = dataTable.Rows[0]["LastName"].ToString();
                        customer.Email = dataTable.Rows[0]["Email"].ToString();
                        customer.PhoneNumber = dataTable.Rows[0]["PhoneNumber"].ToString();

                    }
                    return customer;

                }
            }
        }
}
