using System.ComponentModel.DataAnnotations;

namespace UI.Models
{
    public class Users
    {
        //public int UserId { get; set; }
        //public string UserName { get; set; }
        //public string Password { get; set; }
        [Key]
        public int UserId { get; set; }

        public string Email { get; set; }
        public string Password { get; set; }
        public bool KeepLoggedIn { get; set; }
    }
}
