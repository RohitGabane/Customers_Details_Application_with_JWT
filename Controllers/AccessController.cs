//using Microsoft.AspNetCore.Mvc;
//using System.Security.Authentication;
//using Microsoft.AspNetCore.Authentication.Cookies;
//using UI.Models;
//using System.Security.Claims;
//using Microsoft.AspNetCore.Authentication;

//namespace Customers_Details.Controllers
//{
//    public class AccessController : Controller
//    {
//        public IActionResult Login()
//        {
//            ClaimsPrincipal claimsPrincipal = HttpContext.User;
//            if (claimsPrincipal.Identity.IsAuthenticated) 
//            {
//                return RedirectToAction("Index", "Home");
//            }
//            return View();
//        }
//        [HttpPost]
//        public async Task<IActionResult> Login(Users userlogin)
//        {
//            if (userlogin.Email == "rohitgabane1234@gmail.com" && userlogin.Password == "123") 
//            {
//                List<Claim> claims = new List<Claim>()
//                {
//                    new Claim(ClaimTypes.NameIdentifier,userlogin.Email),
//                    new Claim("otherproperties","Exaple Role")
//                };
//                ClaimsIdentity identity = new ClaimsIdentity(claims,CookieAuthenticationDefaults.AuthenticationScheme);

//                AuthenticationProperties pr
//                    = new AuthenticationProperties()
//                    {
//                        AllowRefresh = true,
//                        IsPersistent=userlogin.KeepLoggedIn
//                    };
//                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity), pr);
//                return RedirectToAction("Index", "Home");  
//            }

//            ViewData["ValidateMessage"] = "user not found";
//            return View();
//        }
//    }
//}
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using UI.Models;

namespace Customers_Details.Controllers
{
    public class AccessController : Controller
    {
        private readonly IConfiguration _configuration;

        public AccessController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public IActionResult Login()
        {
            ClaimsPrincipal claimsPrincipal = HttpContext.User;
            if (claimsPrincipal.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Customers");
            }
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(Users userlogin)
        {
            if (IsValidUser(userlogin.Email, userlogin.Password))
            {
                List<Claim> claims = new List<Claim>()
                {
                    new Claim(ClaimTypes.NameIdentifier, userlogin.Email),
                    new Claim("otherproperties", "Example Role")
                };

                ClaimsIdentity identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

                AuthenticationProperties pr = new AuthenticationProperties()
                {
                    AllowRefresh = true,
                    IsPersistent = userlogin.KeepLoggedIn
                };

                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity), pr);
                return RedirectToAction("Index", "Customers");
            }

            ViewData["ValidateMessage"] = "User not found";
            return View();
        }

        private bool IsValidUser(string email, string password)
        {
            using (SqlConnection sqlConnection = new SqlConnection(_configuration.GetConnectionString("DevConnection")))
            {
                sqlConnection.Open();
                using (SqlCommand cmd = new SqlCommand("ValidateUser", sqlConnection))
                {
                    cmd.CommandType = System.Data.CommandType.StoredProcedure;
                    cmd.Parameters.AddWithValue("@Email", email);
                    cmd.Parameters.AddWithValue("@Password", password);

                    var result = cmd.ExecuteScalar();
                    return result != null && (int)result > 0; // Assuming the stored procedure returns a count or some indication of validity
                }
            }
        }

        ///---------------------------------
        ///
        [HttpGet]
        public IActionResult SignUp()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> SignUp(Users newUser)
        {
            if (ModelState.IsValid)
            {
                if (!IsUserExists(newUser.Email))
                {
                    // Call a stored procedure to create a new user in the database
                    CreateUser(newUser.Email, newUser.Password);

                    // Log in the new user after signup
                    List<Claim> claims = new List<Claim>()
                    {
                        new Claim(ClaimTypes.NameIdentifier, newUser.Email),
                        new Claim("otherproperties", "Example Role")
                    };

                    ClaimsIdentity identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

                    AuthenticationProperties pr = new AuthenticationProperties()
                    {
                        AllowRefresh = true,
                        IsPersistent = newUser.KeepLoggedIn
                    };

                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity), pr);

                    return RedirectToAction("Index", "Customers");
                }
                else
                {
                    ViewData["ValidateMessage"] = "User with this email already exists.";
                }
            }

            return View(newUser);
        }

        private bool IsUserExists(string email)
        {
            using (SqlConnection sqlConnection = new SqlConnection(_configuration.GetConnectionString("DevConnection")))
            {
                sqlConnection.Open();
                using (SqlCommand cmd = new SqlCommand("CheckUserExists", sqlConnection))
                {
                    cmd.CommandType = System.Data.CommandType.StoredProcedure;
                    cmd.Parameters.AddWithValue("@Email", email);

                    var result = cmd.ExecuteScalar();
                    return result != null && (int)result > 0; // Assuming the stored procedure returns a count or some indication of user existence
                }
            }
        }

        private void CreateUser(string email, string password)
        {
            using (SqlConnection sqlConnection = new SqlConnection(_configuration.GetConnectionString("DevConnection")))
            {
                sqlConnection.Open();
                using (SqlCommand cmd = new SqlCommand("CreateUser", sqlConnection))
                {
                    cmd.CommandType = System.Data.CommandType.StoredProcedure;
                    cmd.Parameters.AddWithValue("@Email", email);
                    cmd.Parameters.AddWithValue("@Password", password);

                    cmd.ExecuteNonQuery();
                }
            }
        }
    }
}
