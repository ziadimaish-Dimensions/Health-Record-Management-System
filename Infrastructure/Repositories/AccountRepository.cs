using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Application.Contracts;
using Application.DTOs.Request.Account;
using Application.DTOs.Respose;
using Application.DTOs.Respose.Account;
using Application.Extentions;
using Domain.Entity.Authentication;
using Mapster;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using NotImplementedException = System.NotImplementedException;


namespace Infrastructure.Repositories;

//Injecting the required dependencies
//Dry principle
public class AccountRepository
(RoleManager<IdentityRole> roleManager,
    UserManager<ApplicationUser>userManager, IConfiguration config,
    SignInManager<ApplicationUser> signInManager, AppDbContext context):IAccount
{
    
    private async Task<ApplicationUser> FindUserByEmailAsync(string email)
        => await userManager.FindByEmailAsync(email);
    
    private async Task<IdentityRole> FindRoleByNameAsync(string roleName)
        => await roleManager.FindByNameAsync(roleName);

    private static string GenerateRefreshToken()
        => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

    private async Task<string> GenerateToken(ApplicationUser user)
    {
        try
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]!));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var userClaims = new[]
            {
                new Claim(ClaimTypes.Name, user.Email),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, (await userManager.GetRolesAsync(user)).FirstOrDefault().ToString()),
                new Claim("Fullname", user.Name),
            };
            var token = new JwtSecurityToken(
                issuer: config["Jwt:Issuer"],
                audience: config["Jwt:Audience"],
                expires: DateTime.Now.AddMinutes(30),
                claims: userClaims,
                signingCredentials: credentials
            );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        catch {return null!;}
}

    private async Task<GeneralResponse> AssignUserToRole(ApplicationUser user, IdentityRole role)
    {
        if(user is null || role is null)
            return new GeneralResponse(false, "Model state cannot be empty");
        if (await FindRoleByNameAsync(role.Name) == null)
            await CreateRoleAsync(role.Adapt(new CreateRoleDTO()));
        
        IdentityResult result = await userManager.AddToRoleAsync(user, role.Name);
        string error=CheckResponse(result);
        if(!string.IsNullOrEmpty(error))
            return new GeneralResponse(false, error);
        else
            return new GeneralResponse(true, $"{user.Name} assigned to {role.Name} role");
    }
    
    private string CheckResponse(IdentityResult result)
    {
        if (!result.Succeeded)
        {
            var errors=result.Errors.Select(_=>_.Description);
            return string.Join(Environment.NewLine, errors);
        }

        return null!;
    }
    
    public async Task CreateAdmin()
    {
        try
        {
            if ((await FindRoleByNameAsync(Constant.Role.Admin)) != null) return;
            var admin = new CreateAccountDTO()
            {
                Name = "Admin",
                Password = "1q2w3E*9",
                EmailAddress = "admin@asp.net",
                Role = Constant.Role.Admin
            };
            await CreateAccountAsync(admin);
        }
        catch
        {
            
        }
    }

    public async Task<GeneralResponse> CreateAccountAsync(CreateAccountDTO model)
    {
        try
        {
            if(await FindUserByEmailAsync(model.EmailAddress)!=null)
                return new GeneralResponse(false, "Sorry, user already exists");
            var user = new ApplicationUser()
            {
                Name = model.Name,
                UserName = model.EmailAddress,
                Email = model.EmailAddress,
                PasswordHash = model.Password
            };
            var result = await userManager.CreateAsync(user, model.Password);
            string error = CheckResponse(result);
            if (!string.IsNullOrEmpty(error))
                return new GeneralResponse(false, error);
            
            var (flag, message) = await AssignUserToRole(user, new IdentityRole(){Name=model.Role});
            return new GeneralResponse(flag, message);
        }
        catch (Exception ex)
        {
            return new GeneralResponse(false,ex.Message);
        }
    }

    public async Task<LoginResponse> LoginAccountAsync(LoginDTO model)
    {
        try
        {
            var user = await FindUserByEmailAsync(model.EmailAddress);
            if (user is null)
                return new LoginResponse(false, "User not found");
            SignInResult result;
            try
            {
                result = await signInManager.CheckPasswordSignInAsync(user, model.Password, false);
            }
            catch
            {
                return new LoginResponse(false, "Invalid credentials");
            }

            if (!result.Succeeded)
                return new LoginResponse(false, "Invalid credentials");
            string jwtToken = await GenerateToken(user);
            string refreshToken = GenerateRefreshToken();
            if (string.IsNullOrEmpty(jwtToken) || string.IsNullOrEmpty(refreshToken))
                return new LoginResponse(false,
                    "Error occured while logging in account, please contact administration");
            else
            {
                var saveResult=await SaveRefreshToken(user.Id, refreshToken);
                if(saveResult.flag)
                    return new LoginResponse(true, $"{user.Name} successfully logged in", jwtToken, refreshToken);
                else
                    return new LoginResponse();

            }
        }
        catch (Exception ex)
        {

            return new LoginResponse(false, ex.Message);
        }
    }

    public async Task<LoginResponse> RefreshTokenAsync(RefreshTokenDTO model)
    {
        var token=await context.RefreshTokens.FirstOrDefaultAsync(t=> t.Token == model.Token);
        if (token == null) return new LoginResponse();
        var user = await userManager.FindByIdAsync(token.UserId);
        string newToken = await GenerateToken(user);
        string newRefreshToken = GenerateRefreshToken();
        var saveResult = await SaveRefreshToken(user.Id, newRefreshToken);//update it
        if(saveResult.flag)
            return new LoginResponse(true, $"{user.Name} successfully logged in", newToken, newRefreshToken);
        else
            return new LoginResponse();
    }

    public Task<GeneralResponse> CreateRoleAsync(CreateRoleDTO model)
    {
        throw new NotImplementedException();
    }

    public async Task<IEnumerable<GetRoleDTO>> GetRolesAsync() =>
        (await roleManager.Roles.ToListAsync()).Adapt<IEnumerable<GetRoleDTO>>();
    
    public async Task<IEnumerable<GetUsersWithRolesResponseDTO>> GetUsersWithRolesAsync()
    {
        var allusers=await userManager.Users.ToListAsync();
        if (allusers is null) return null;
        var List=new List<GetUsersWithRolesResponseDTO>();
        foreach (var user in allusers)
        {
            var getUserRole = (await userManager.GetRolesAsync(user)).FirstOrDefault();
            var getRoleInfo =
                await roleManager.Roles.FirstOrDefaultAsync(r => r.Name.ToLower() == getUserRole.ToLower());
            List.Add(new GetUsersWithRolesResponseDTO()
            {
                Name=user.Name,
                Email=user.Email,
                RoleId = getRoleInfo.Id,
                RoleName = getRoleInfo.Name
            });
        }

        return List;
    }

    public async Task<GeneralResponse> ChangeUserRoleAsync(ChangeUserRoleRequestDTO model)
    {
        if(await FindRoleByNameAsync(model.RoleName)is null)return new GeneralResponse(false, "Role not found");
        if(await FindRoleByNameAsync(model.UserEmail)is null)return new GeneralResponse(false, "User not found");
        
        var user = await FindUserByEmailAsync(model.UserEmail);
        var previousRole = (await userManager.GetRolesAsync(user)).FirstOrDefault();
        var removeOldRole=await userManager.RemoveFromRoleAsync(user, previousRole);
        var error = CheckResponse(removeOldRole);
        if (!string.IsNullOrEmpty(error))
            return new GeneralResponse(false, error);
        var result = await userManager.AddToRoleAsync(user, model.RoleName);
        var response = CheckResponse(result);
        if (!string.IsNullOrEmpty(error))
            return new GeneralResponse(false, response);
        else
            return new GeneralResponse(true, "Role Changed");
    }

    private async Task<GeneralResponse> SaveRefreshToken(string userId, string token)
    {
        try
        {
            var user = await context.RefreshTokens.FirstOrDefaultAsync(t => t.UserId == userId);
            if (user == null)
                context.RefreshTokens.Add(new RefreshToken() { UserId = userId, Token = token });
            else
                user.Token = token;
            await context.SaveChangesAsync();
            return new GeneralResponse(true, null!);
        }
        catch (Exception ex)
        {
            return new GeneralResponse(false, ex.Message);
        }
    }
}