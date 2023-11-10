using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Npgsql;
using System.Collections.Generic;

public class VulnerableModel : PageModel
{
    private readonly string _connectionString;

    public VulnerableModel(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("DefaultConnection");
    }

    [BindProperty]
    public string Username { get; set; }

    [BindProperty]
    public string Password { get; set; }

    [BindProperty]
    public string IsVulnerable { get; set; } 
    [BindProperty]
    public string NewUsername { get; set; }

    [BindProperty]
    public string NewPassword { get; set; }

    [BindProperty]
    public string AllowSimplePassword { get; set; }

    public string Message { get; set; }

    public string Message2 { get; set; }
    public void OnPost()
    {
        var action = Request.Form["action"];

        if (action == "Prijava")
        {
            HandleSqlInjection();
        }
        else if (action == "Kreiraj profil")
        {
            OnPostCreateAccount();
        }
    }
    private void HandleSqlInjection()
    {
        using (var connection = new NpgsqlConnection(_connectionString))
        {
            connection.Open();
            
            if (IsVulnerable == "true")
            {
                
                var commandText = $"SELECT * FROM Users WHERE Username = '{Username}' AND Password = '{Password}'";
                var command = new NpgsqlCommand(commandText, connection);
                ExecuteCommand(command);
            }
            else
            {
                
                var commandText = "SELECT * FROM Users WHERE Username = @username AND Password = @password";
                var command = new NpgsqlCommand(commandText, connection);
                command.Parameters.AddWithValue("@username", Username ?? string.Empty);
                command.Parameters.AddWithValue("@password", Password ?? string.Empty);
                ExecuteCommand(command);
            }
        }
    }

    private void ExecuteCommand(NpgsqlCommand command)
    {
        using (var reader = command.ExecuteReader())
        {
            var results = new List<string>();
            while (reader.Read())
            {
                var row = new List<string>();
                for (int col = 0; col < reader.FieldCount; col++)
                {
                    var columnName = reader.GetName(col);
                    var columnValue = reader.GetValue(col);
                    row.Add($"{columnName}: {columnValue}");
                }
                results.Add(string.Join(", ", row));
            }

            if (results.Any())
            {
                Message = string.Join("\n", results);
            }
            else
            {
                Message = "Nepostojeći korisnik.";
            }
        }
    }
    public void OnPostCreateAccount()
    {
        if (AllowSimplePassword == "true")
        {
            if (NewPassword.Length < 4)
            {
                Message2 = "Lozinka treba imati barem 4 znaka.";
                return;
            }
        }
        else
        {
            if (!IsPasswordComplex(NewPassword))
            {
                Message2 = "Lozinka treba imati barem 8 znakova, jedno veliko slovo, jedno malo slovo, jedan broj i jedan specijalni znak.";
                return;
            }
        }

        
        using (var connection = new NpgsqlConnection(_connectionString))
        {
            connection.Open();

            var commandText = "INSERT INTO Users (Username, Password) VALUES (@username, @password)";
            using (var command = new NpgsqlCommand(commandText, connection))
            {
                command.Parameters.AddWithValue("@username", NewUsername ?? string.Empty);
                command.Parameters.AddWithValue("@password", NewPassword ?? string.Empty);
                command.ExecuteNonQuery();
            }
        }

        Message2 = "Profil je uspješno kreiran.";
    }
    private bool IsPasswordComplex(string password)
    {
        return password.Length >= 8 &&
               password.Any(char.IsUpper) &&
               password.Any(char.IsLower) &&
               password.Any(char.IsDigit) &&
               password.Any(ch => !char.IsLetterOrDigit(ch));
    }

}
