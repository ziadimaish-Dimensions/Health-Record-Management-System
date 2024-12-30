using System.ComponentModel.DataAnnotations;

namespace Application.DTOs.Request.Account;

public class LoginDTO
{
    [EmailAddress, Required, DataType(DataType.EmailAddress)]
    [RegularExpression("[^@ \\t\\r\\n]+@[^@ \\t\\r\\n]+.[^@\\t\\r\\n]+",
        ErrorMessage = "Your Email is not valid, provide valid email such as example@gmail.com")]
            [Display (Name = "Email Address")]
    
    public string EmailAddress { get; set; }= string.Empty;

    [Required]
    [RegularExpression("^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?! @$ g^&*-]).{8, 3$",
        ErrorMessage = "You password must be a mix of Alphanumeric and special characters")]
    
    public string Password { get; set; }=string.Empty;
}
