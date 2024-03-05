using System.ComponentModel.DataAnnotations;

namespace AspNet7WebApiAuth.Core.DTOs
{
    public class UpdatePermissionDTO
    {
        [Required(ErrorMessage = "UserName is Required")]
        public string UserName { get; set; }

    }
}
