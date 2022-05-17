using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Collections.Generic;
using System.Security.Claims;
using System.Linq;

namespace JwtAuthLab.Filters
{
    public class BlackFilter : IAuthorizationFilter
    {
        public static List<string> _bannedList = new List<string>()
            { "bad", "dad" }; //可預先加些資料，測試filter的效果
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var name = context.HttpContext.User.Claims
                .FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;

            if (_bannedList.Contains(name))
                context.Result = new ForbidResult();
        }
    }
}
