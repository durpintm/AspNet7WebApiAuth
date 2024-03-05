using AspNet7WebApiAuth.Core.DTOs;

namespace AspNet7WebApiAuth.Core.Interfaces
{
    public interface IAuthService
    {
        Task<AuthServiceResponseDTO> SeedRoleAsync();
        Task<AuthServiceResponseDTO> RegisterAsync(RegisterDTO registerDto);
        Task<AuthServiceResponseDTO> LoginAsync(LoginDTO loginDto);
        Task<AuthServiceResponseDTO> MakeAdminAsync(UpdatePermissionDTO updatePermissionDto);
        Task<AuthServiceResponseDTO> MakeOwnerAsync(UpdatePermissionDTO updatePermissionDto);
    }
}
