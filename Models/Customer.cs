using System.ComponentModel.DataAnnotations;

namespace UI.Models
{
    public class Customer
    {
        [Key]
        public int CustomerId { get; set; }
        [Required(ErrorMessage = "First Name is required.")]
        [RegularExpression(@"^[a-zA-Z]+$", ErrorMessage = "First Name should contain only letters.")]
        public string? FirstName { get; set; }
        [Required(ErrorMessage = "Last Name is required.")]
        [RegularExpression(@"^[a-zA-Z]+$", ErrorMessage = "Last Name should contain only letters.")]
        public string? LastName { get; set; }
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid Email Address.")]
        public string? Email { get; set; }
        [Required(ErrorMessage = "Phone Number is required.")]
        [RegularExpression(@"^[0-9]+$", ErrorMessage = "Phone Number should contain only numbers.")]
        public string? PhoneNumber { get; set; }
    }
}
