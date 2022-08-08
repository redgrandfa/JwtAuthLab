using JwtAuthLab.Filters;
using JwtAuthLab.Helpers;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace JwtAuthLab
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
            services.AddControllersWithViews();
            services.AddScoped<JwtHelper>();
            services.AddHttpContextAccessor();

            //設定token驗證機制
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
              .AddJwtBearer(options =>
              {
                  options.IncludeErrorDetails = true;
                  options.TokenValidationParameters = new TokenValidationParameters
                  {
                      // 透過這項宣告，就可以從 "sub" 取值並設定給 User.Identity.Name  (試不出差別...)
                      //NameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
                      // 透過這項宣告，就可以從 "roles" 取值，並可讓 [Authorize] 判斷角色 (不需要也行...)
                      //RoleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",

                      //是否驗發行者
                      ValidateIssuer = true,
                      //設定有效的發行者，須和發行時的發行者一致，才能過驗
                      ValidIssuer = Configuration.GetValue<string>("JwtSettings:Issuer"),

                      // 是否驗Audience。通常沒設定Audience，就不驗
                      ValidateAudience = false,

                      // 是否驗Token的有效期間(應該是根據 notBefore 和 expires )。通常會驗
                      ValidateLifetime = true,
                      //LifetimeValidator = ...,  //這屬性是個委派，檢驗notBefore和 expires，筆者沒試過

                      // 參考文章註解說：如果 Token 中包含 key 才需要驗證，一般都只有簽章而已
                      // 筆者看不懂，而文章內是設為false
                      ValidateIssuerSigningKey = true,
                      //設定有效的私鑰，須和發行時的私鑰一致，才能過驗
                      IssuerSigningKey =
                          new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                              Configuration.GetValue<string>("JwtSettings:SignKey")
                          ))
                  };
              });

            //註冊Filter
            services.AddControllers(options =>
            {
                options.Filters.Add(new BlackFilter());
            });

            // Register the Swagger generator, defining 1 or more Swagger documents
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { 
                    Title = "Swagger首頁標題", 
                    Version = "v1" 
                    //還有幾個屬性可以設定
                });

                // Set the comments path for the Swagger JSON and UI.
                var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
                var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                c.IncludeXmlComments(xmlPath);

                #region 這段複製貼上
                // swagger 加入 jwt 支援
                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
                {
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "Bearer",
                    BearerFormat = "JWT",
                    Description = "JWT Authorization header using the Bearer scheme."
                });

                c.AddSecurityRequirement(new OpenApiSecurityRequirement()
                {
                    { 
                        new OpenApiSecurityScheme(){ }, 
                        new List<string>() 
                    }
                });

                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            }
                        },
                        new string[] {}
                    }
                });
                #endregion
            });

            //services.AddAuthorization(opt =>
            //{
            //    opt.DefaultPolicy 
            //    opt.AddPolicy("", policy => { });
            //});
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                // Enable middleware to serve generated Swagger as a JSON endpoint.
                app.UseSwagger();

                // Enable middleware to serve swagger-ui (HTML, JS, CSS, etc.)
                app.UseSwaggerUI(c => {
                    c.SwaggerEndpoint("/swagger/v1/swagger.json", "定義名稱 v1");
                    c.RoutePrefix = string.Empty;
                    //c.InjectStylesheet("/swagger-ui/custom.css");
                });
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}"
                );//.RequireAuthorization();
            });
        }
    }
}
