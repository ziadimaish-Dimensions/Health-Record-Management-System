using Application.DTOs.Request.Account;
using Application.DTOs.Respose;
using Application.DTOs.Respose.Account;

namespace Application.Contracts;

public interface IAccount
{
     //create admin account first time runs
     Task CreateAdmin();
     Task<GeneralResponse> CreateAccountAsync(CreateAccountDTO model);
     Task<LoginResponse> LoginAccountAsync(LoginDTO model);
     
     Task<LoginResponse> RefreshTokenAsync(RefreshTokenDTO model);
     
     Task<GeneralResponse> CreateRoleAsync(CreateRoleDTO model);
     Task<IEnumerable<GetRoleDTO>> GetRolesAsync();
     Task<IEnumerable<GetUsersWithRolesResponseDTO>> GetUsersWithRolesAsync();
     Task<GeneralResponse> ChangeUserRoleAsync(ChangeUserRoleRequestDTO model);
     
     
}