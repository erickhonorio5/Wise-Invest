using System.ComponentModel.DataAnnotations;

namespace Auth.API.Models;

public class RegisterUser
{
    [Required(ErrorMessage = "O campo {0} é obrigatório")]
    [EmailAddress(ErrorMessage = "O campo {0} está em formato inválido")]
    public string Email { get; set; }

    [Required(ErrorMessage = "O campo {0} é obrigatório")]
    [StringLength(100, ErrorMessage = "O campo {0} precisa ter entre {2} e {1} caracteres", MinimumLength = 6)]
    public string Password { get; set; }

    [Compare("Password", ErrorMessage = "As senhas não conferem.")]
    public string ConfirmPassword { get; set; }
}

public class LoginUser
{
    [Required(ErrorMessage = "O campo {0} é obrigatório")]
    [EmailAddress(ErrorMessage = "O campo {0} está em formato inválido")]
    public string Email { get; set; }

    [Required(ErrorMessage = "O campo {0} é obrigatório")]
    [StringLength(100, ErrorMessage = "O campo {0} precisa ter entre {2} e {1} caracteres", MinimumLength = 6)]
    public string Password { get; set; }
}

public class UserLoginResponse 
{
    public string AccessToken { get; set; }
    public double ExpiresIn { get; set; }
    public UserToken UserToken { get; set; }
}

public class UserToken
{
    public string Id { get; set; }
    public string Email { get; set; }
    public IEnumerable<ClaimViewModel> Claims { get; set; }
}

public class LoginResponse
{
    public string AccessToken { get; set; }
    public double ExpiresIn { get; set; }
    public UserToken UserToken { get; set; }
}

public class ClaimViewModel
{
    public string Value { get; set; }
    public string Type { get; set; }
}
