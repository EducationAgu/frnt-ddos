using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using WebApi.Helpers;
using WebApi.Services;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using WebApi.Entities;
using System;

namespace WebApi
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // docker run -d --name olya -e POSTGRES_PASSWORD=postgres -e  POSTGRES_USER=postgres -e POSTGRES_DB=jwt --restart always -p "1212:5432" postgres
            services.AddDbContext<DataContext>(options =>
            {
                options.UseNpgsql("Username=postgres; Database=jwt; Password=postgres; Host=localhost; Port=1212");
            });

            services.AddCors();
            services.AddControllers().AddJsonOptions(x => x.JsonSerializerOptions.IgnoreNullValues = true);

            // configure strongly typed settings objects
            var appSettingsSection = Configuration.GetSection("AppSettings");
            services.Configure<AppSettings>(appSettingsSection);

            // configure jwt authentication
            var appSettings = appSettingsSection.Get<AppSettings>();
            var key = Encoding.ASCII.GetBytes(appSettings.Secret);
            services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(x =>
            {
                x.RequireHttpsMetadata = false;
                x.SaveToken = true;
                x.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                    ClockSkew = TimeSpan.Zero
                };
            });

            // configure DI for application services
            services.AddTransient<IUserService, UserService>();

            services.AddScoped<IDocumentService, DocumentService>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, DataContext context)
        {
            // add hardcoded test user to db on startup
            // plain text password is used for simplicity, hashed passwords should be used in production applications
            /*  context.Users.Add(new User { Id = 1, FirstName = "User", LastName = "1", Username = "username_1", Password = BCrypt.Net.BCrypt.HashPassword("test")});
              context.Users.Add(new User { Id = 2, FirstName = "UseR", LastName = "2", Username = "username_2", Password = BCrypt.Net.BCrypt.HashPassword("test2")}); 

              context.Documents.Add(new Document() { Id = 1, Name = "name 1", Data = "data for document 1", UserId = 1});
              context.Documents.Add(new Document() { Id = 2, Name = "name 2", Data = "data for document 2", UserId = 1 });
              context.Documents.Add(new Document() { Id = 3, Name = "name 3", Data = "data for document 3", UserId = 1 });
              context.Documents.Add(new Document() { Id = 4, Name = "name 4", Data = "data for document 4", UserId = 2 });

              context.SaveChanges();
            */
            app.UseRouting();

            // global cors policy
            app.UseCors(x => x
                .SetIsOriginAllowed(origin => true)
                .AllowAnyMethod()
                .AllowAnyHeader()
                .AllowCredentials());

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(x => x.MapControllers());
        }
    }
}
