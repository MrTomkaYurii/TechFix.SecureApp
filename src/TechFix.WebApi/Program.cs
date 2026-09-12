using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using TechFix.Application.Interfaces;
using TechFix.Infrastructure.Persistence;
using TechFix.Infrastructure.Services;

var builder = WebApplication.CreateBuilder(args);

// 1. Add Controllers
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// 2. Configure Swagger with university metadata
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "TechFix Enterprise - Secure Software Development Platform",
        Version = "v1.0 (Магістерський практикум)",
        Description = "Навчально-дослідний стенд для демонстрації вразливостей OWASP Top 10 та практик Secure by Design.\n\n" +
                      "Виконав: магістр групи СНм-61 Томка Юрій Ярославович\n" +
                      "Перевірив: к.т.н., доцент Козак Руслан Орестович\n" +
                      "ТНТУ ім. Івана Пулюя, Кафедра комп'ютерних наук, 2026 рік.",
        Contact = new OpenApiContact
        {
            Name = "Томка Юрій (СНм-61)",
            Email = "tomka.yurii@tntu.edu.ua"
        }
    });

    // Support XML comments if available
    var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    if (File.Exists(xmlPath))
    {
        c.IncludeXmlComments(xmlPath);
    }
});

// 3. Configure Database (SQLite)
var dbPath = Path.Combine(AppContext.BaseDirectory, "techfix_security.db");
builder.Services.AddDbContext<TechFixDbContext>(options =>
    options.UseSqlite($"Data Source={dbPath}"));

// 4. Register Clean Architecture Application/Infrastructure Services
builder.Services.AddScoped<IInjectionService, InjectionService>();
builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();
builder.Services.AddScoped<IXxeService, XxeService>();
builder.Services.AddScoped<IAccessControlService, AccessControlService>();

// 5. Configure CORS
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

var app = builder.Build();

// 6. Ensure Database Created & Seeded
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<TechFixDbContext>();
    db.Database.EnsureCreated();
}

// 7. Configure HTTP pipeline
app.UseStaticFiles();
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "TechFix Security API v1");
    c.RoutePrefix = string.Empty; // Swagger at root http://localhost:5000/
    c.DocumentTitle = "TechFix Security Platform - ТНТУ ТРЗПЗ";
});

app.UseCors();
app.UseAuthorization();
app.MapControllers();

app.Run();
