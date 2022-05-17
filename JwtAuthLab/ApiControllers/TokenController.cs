using JwtAuthLab.Filters;
using JwtAuthLab.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;

namespace JwtAuthLab.ApiControllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    [Authorize]
    public class TokenController : ControllerBase
    {
        private readonly JwtHelper _jwtHelper;

        public TokenController(JwtHelper jwtHelper)
        {
            _jwtHelper = jwtHelper;
        }

        /// <summary>
        ///     【會出現在API標題】
        /// </summary>
        /// <remarks>
        ///     【會出現在API內部剛開始的說明處】
        ///     【文件說這裡面內容可以包含文字、JSON 或 XML。】
        /// 下方須隔一行且有縮排，才會變成小標題
        ///
        ///     GET /TestAuth
        ///     {
        ///         "prop1": [1,2,3]
        ///     }
        /// 下方須隔一行且有縮排，才會變成小標題
        ///
        ///     亂
        ///         寫
        ///             也
        ///                 行
        ///                     }
        /// </remarks>
        /// <param name="request">【會出現在參數說明】</param>
        /// <returns> 回傳說明 </returns>
        /// <response code="200">【會在description區，描述此回應類型】</response>
        /// <response code="404">【會在description區，描述此回應類型】</response>            
        [HttpPost]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [AllowAnonymous]
        //進此action之前，會先進入BlackFilter
        //但因為未攜帶JWT，故無妨
        public ActionResult<string> SignIn(LoginVM request)
        {
            BlackFilter._bannedList.Remove(request.Username);
            return Ok(_jwtHelper.GenerateJWT(request.Username));
        }

        //僅為了demo方便，將類別放在此
        public class LoginVM
        {
            public string Username { get; set; }
            public string Password { get; set; }
        }

        [HttpGet]
        public IActionResult SignOut()
        {
            var name = User.Claims
                .FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;

            BlackFilter._bannedList.Add(name);
            return Ok($"登出了{name}，加進過濾名單");
        }

        [HttpGet]
        public IActionResult TestAuth()
        {
            return Ok($"驗證類型：{User.Identity.AuthenticationType}\n" +
                        $"通驗否：{User.Identity.IsAuthenticated}\n" +
                        $"你是 {User.Identity.Name}"
                    );
        }


        //三個實用的API
        [HttpGet("claims")]
        public IActionResult GetClaims()
        {
            return Ok(User.Claims.Select(c => new { c.Type, c.Value }));
        }

        [HttpGet("/sub")]
        public IActionResult GetSub()
        {
            //var sub = User.Claims.FirstOrDefault(p => p.Type == JwtRegisteredClaimNames.Sub); //實際上不存在
            var sub = User.Claims.FirstOrDefault(p => p.Type == 
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");
            return Ok(sub?.Value);
        }

        [HttpGet("~/jti")]
        public IActionResult GetJti()
        {
            var jti = User.Claims.FirstOrDefault(p => p.Type == JwtRegisteredClaimNames.Jti);
            return Ok(jti?.Value);
        }

    }
}
