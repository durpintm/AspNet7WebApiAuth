using System.ComponentModel.DataAnnotations;

namespace AspNet7WebApiAuth.Core.DTOs
{
    public class RegisterDTO
    {
        [Required(ErrorMessage = "UserName is Required")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Email is Required")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is Required")]
        public string Password { get; set; }
    }
}
