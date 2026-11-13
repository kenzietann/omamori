// A small ASP.NET Core minimal API with Serilog request logging in compact JSON, the most common way to log
// requests in ASP.NET Core. The address of the client is added to each request line, as its docs show.
using Serilog;
using Serilog.Formatting.Compact;

Log.Logger = new LoggerConfiguration().WriteTo.Console(new RenderedCompactJsonFormatter()).CreateLogger();
var builder = WebApplication.CreateBuilder(args);
builder.Host.UseSerilog();
var app = builder.Build();
app.UseSerilogRequestLogging(options =>
    options.EnrichDiagnosticContext = (context, http) => context.Set("RemoteIpAddress", http.Connection.RemoteIpAddress?.ToString()));

app.MapPost("/auth/login", (Credentials body, HttpContext http, ILogger<Program> logger) =>
{
    if (body.username == "alice" && body.password == "Summer2026!") return Results.Ok(new { token = "t" });
    logger.LogWarning("Failed login for {User} from {ClientIp}", body.username, http.Connection.RemoteIpAddress?.ToString());
    return Results.Json(new { error = "invalid credentials" }, statusCode: 401);
});
app.MapGet("/api/items", (string? id, ILogger<Program> logger) =>
{
    if (id is not null && id.Contains('\''))
    {
        logger.LogError("Microsoft.Data.SqlClient.SqlException: Incorrect syntax near '{Id}'.", id);
        return Results.Json(new { error = "server error" }, statusCode: 500);
    }
    return Results.Ok(Array.Empty<string>());
});
app.Run("http://0.0.0.0:8080");

record Credentials(string username, string password);
