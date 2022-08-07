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
            { "1","2" }; //可預先加些資料，測試filter的效果
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var memberId = context.HttpContext.User.Identity?.Name;
                
            if (_bannedList.Contains(memberId))
                context.Result = new ForbidResult();
        }
    }
}
