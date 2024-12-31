using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Application.DTOs.Request.Account;
using Application.DTOs.Respose.Account;
using Application.Extentions;
using Microsoft.AspNetCore.Components.Authorization;

namespace Application.Extensions;

public class CustomAuthenticationStateProvide(LocalStorageService localStorageService) : AuthenticationStateProvider
{
    private readonly ClaimsPrincipal anonymous = new(new ClaimsIdentity());

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var tokenModel = await localStorageService.GetModelFromToken();
        if (string.IsNullOrEmpty(tokenModel.Token))
            return await Task.FromResult(new AuthenticationState(anonymous));

        var getUserClaims = DecryptToken(tokenModel.Token!);
        if (getUserClaims == null) return await Task.FromResult(new AuthenticationState(anonymous));

        var claimsPrincipal = SetClaimsPrincipal(getUserClaims);
        return await Task.FromResult(new AuthenticationState(claimsPrincipal));
    }

    public async Task UpdateAutheticationState(LocalStorageDto localStorageDto)
    {
        var claimsPrincipal = new ClaimsPrincipal();
        if(localStorageDto.Token != null||localStorageDto.RefreshToken!=null)
        {
            await localStorageService.SetBrowserLocalStorage(localStorageDto);
            var getUserClaims = DecryptToken(localStorageDto.Token!);
            claimsPrincipal = SetClaimsPrincipal(getUserClaims);
        }
        else
        {
            await localStorageService.RemoveTokenFromBrowserLocalStorage();
        }
        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(claimsPrincipal)));
    }

    public static ClaimsPrincipal SetClaimsPrincipal(UserClaimsDTO claims)
    {
        if (claims.Email is null) return new ClaimsPrincipal();
        return new ClaimsPrincipal(new ClaimsIdentity(
        [
            new(ClaimTypes.Name, claims.UserName!),
            new(ClaimTypes.Email, claims.Email!),
            new(ClaimTypes.Role, claims.Role!),
            new Claim
                ("Fullname", claims.Fullname),
        ], Constant.AuthenticationType));
    }
    
    private static UserClaimsDTO DecryptToken(string jwtToken)
    {
        try
        {
            if (string.IsNullOrEmpty(jwtToken)) return new UserClaimsDTO();

            var handler = new JwtSecurityTokenHandler();
            var token=handler.ReadJwtToken(jwtToken);
            
            var name=token.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Name)!.Value;
            var email=token.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Email)!.Value;
            var role=token.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Role)!.Value;
            var fullname=token.Claims.FirstOrDefault(x => x.Type == "Fullname")!.Value;
            return new UserClaimsDTO(fullname,name,email,role);
        }
        catch
        {
            return null!;
        }
    }
}