using Application.DTOs.Request.Account;
using Application.DTOs.Respose;
using Application.DTOs.Respose.Account;

namespace Application.Services;

public interface IAccountService
{
    Task CreateAdmin();
    Task<GeneralResponse> CreateAccountAsync(CreateAccountDTO model);
    Task<LoginResponse> LoginAccountAsync(LoginDTO model);
    Task<LoginResponse> RefreshTokenAsync(RefreshTokenDTO model);
    Task<IEnumerable<GetRoleDTO>> GetRolesAsync();
    Task<IEnumerable<GetUsersWithRolesResponseDTO>> GetUsersWithRolesAsync();
    Task<GeneralResponse> ChangeUserRoleAsync(ChangeUserRoleRequestDTO model);

}