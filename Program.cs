using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Claims;
using System.Collections.Concurrent;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Add JWT authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = "yourissuer",
            ValidAudience = "youraudience",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("supersecretkeyatleast32charslong"))
        };
    });

builder.Services.AddAuthorization();

// In-memory user store (use a database in production!)
var userStore = new ConcurrentDictionary<string, UserInfo>();

var app = builder.Build();

// Configure to run on port 5001
app.Urls.Add("http://localhost:5001");

app.UseSwagger();
app.UseSwaggerUI();

app.UseAuthentication();
app.UseAuthorization();

// Signup endpoint
app.MapPost("/signup", (SignupRequest request) =>
{
    // Validate input
    if (string.IsNullOrWhiteSpace(request.Username) || request.Username.Length < 3)
    {
        return Results.BadRequest("Username must be at least 3 characters long");
    }

    if (string.IsNullOrWhiteSpace(request.Password) || request.Password.Length < 6)
    {
        return Results.BadRequest("Password must be at least 6 characters long");
    }

    if (string.IsNullOrWhiteSpace(request.Email))
    {
        return Results.BadRequest("Email is required");
    }

    // Check if user already exists
    if (userStore.ContainsKey(request.Username.ToLower()))
    {
        return Results.BadRequest("Username already exists");
    }

    // Hash password (simple hashing for demo - use bcrypt/argon2 in production!)
    var hashedPassword = HashPassword(request.Password);

    // Store user
    var user = new UserInfo
    {
        Username = request.Username,
        PasswordHash = hashedPassword,
        Email = request.Email,
        CreatedAt = DateTime.UtcNow
    };

    userStore.TryAdd(request.Username.ToLower(), user);

    return Results.Ok(new
    {
        message = "User created successfully",
        username = request.Username,
        email = request.Email
    });
}).AllowAnonymous();

// Login endpoint
app.MapPost("/login", (LoginRequest request) =>
{
    if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
    {
        return Results.BadRequest("Username and password are required");
    }

    // Check if user exists
    if (!userStore.TryGetValue(request.Username.ToLower(), out var user))
    {
        return Results.Unauthorized();
    }

    // Verify password
    if (!VerifyPassword(request.Password, user.PasswordHash))
    {
        return Results.Unauthorized();
    }

    // Generate JWT token
    var claims = new[]
    {
        new Claim(ClaimTypes.Name, user.Username),
        new Claim(ClaimTypes.Email, user.Email),
        new Claim(ClaimTypes.Role, "User")
    };

    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("supersecretkeyatleast32charslong"));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
        issuer: "yourissuer",
        audience: "youraudience",
        claims: claims,
        expires: DateTime.Now.AddMinutes(30),
        signingCredentials: creds);

    return Results.Ok(new
    {
        token = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(token),
        expiresAt = DateTime.Now.AddMinutes(30),
        username = user.Username
    });
}).AllowAnonymous();

// Get current user info (protected endpoint)
app.MapGet("/me", (HttpContext context) =>
{
    var username = context.User.FindFirst(ClaimTypes.Name)?.Value;
    var email = context.User.FindFirst(ClaimTypes.Email)?.Value;

    return Results.Ok(new
    {
        username = username,
        email = email
    });
}).RequireAuthorization();

// List all users (for testing - remove in production!)
app.MapGet("/users", () =>
{
    return Results.Ok(userStore.Values.Select(u => new
    {
        username = u.Username,
        email = u.Email,
        createdAt = u.CreatedAt
    }));
}).RequireAuthorization();

app.Run();

// Helper methods
string HashPassword(string password)
{
    using var sha256 = SHA256.Create();
    var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
    return Convert.ToBase64String(hashedBytes);
}

bool VerifyPassword(string password, string hashedPassword)
{
    var hashOfInput = HashPassword(password);
    return hashOfInput == hashedPassword;
}

// Models
public record SignupRequest(string Username, string Password, string Email);
public record LoginRequest(string Username, string Password);

public class UserInfo
{
    public string Username { get; set; }
    public string PasswordHash { get; set; }
    public string Email { get; set; }
    public DateTime CreatedAt { get; set; }
}