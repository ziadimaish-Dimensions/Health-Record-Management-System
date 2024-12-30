using System.ComponentModel.DataAnnotations;

namespace Application.DTOs.Request.Account;

public class CreateAccountDTO : LoginDTO
{
    [Required]
    public String Name { get; set; } = string.Empty;
    [Required, Compare(nameof(Password))]
    public String ConfirmPassword { get; set; } = string.Empty;
    [Required]
    public String Role {get; set;} = string.Empty;
}