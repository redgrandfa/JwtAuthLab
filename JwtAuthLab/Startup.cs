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

            //�]�wtoken���Ҿ���
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
              .AddJwtBearer(options =>
              {
                  options.IncludeErrorDetails = true;
                  options.TokenValidationParameters = new TokenValidationParameters
                  {
                      // �z�L�o���ŧi�A�N�i�H�q "sub" ���Ȩó]�w�� User.Identity.Name  (�դ��X�t�O...)
                      //NameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
                      // �z�L�o���ŧi�A�N�i�H�q "roles" ���ȡA�åi�� [Authorize] �P�_���� (���ݭn�]��...)
                      //RoleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",

                      //�O�_��o���
                      ValidateIssuer = true,
                      //�]�w���Ī��o��̡A���M�o��ɪ��o��̤@�P�A�~��L��
                      ValidIssuer = Configuration.GetValue<string>("JwtSettings:Issuer"),

                      // �O�_��Audience�C�q�`�S�]�wAudience�A�N����
                      ValidateAudience = false,

                      // �O�_��Token�����Ĵ���(���ӬO�ھ� notBefore �M expires )�C�q�`�|��
                      ValidateLifetime = true,
                      //LifetimeValidator = ...,  //�o�ݩʬO�өe���A����notBefore�M expires�A���̨S�չL

                      // �ѦҤ峹���ѻ��G�p�G Token ���]�t key �~�ݭn���ҡA�@�볣�u��ñ���Ӥw
                      // ���̬ݤ����A�Ӥ峹���O�]��false
                      ValidateIssuerSigningKey = true,
                      //�]�w���Ī��p�_�A���M�o��ɪ��p�_�@�P�A�~��L��
                      IssuerSigningKey =
                          new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                              Configuration.GetValue<string>("JwtSettings:SignKey")
                          ))
                  };
              });

            //���UFilter
            services.AddControllers(options =>
            {
                options.Filters.Add(new BlackFilter());
            });

            // Register the Swagger generator, defining 1 or more Swagger documents
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { 
                    Title = "Swagger�������D", 
                    Version = "v1" 
                    //�٦��X���ݩʥi�H�]�w
                });

                // Set the comments path for the Swagger JSON and UI.
                var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
                var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                c.IncludeXmlComments(xmlPath);

                #region �o�q�ƻs�K�W
                // swagger �[�J jwt �䴩
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
                    c.SwaggerEndpoint("/swagger/v1/swagger.json", "�w�q�W�� v1");
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
