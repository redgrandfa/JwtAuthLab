using JwtAuthLab.Filters;
using JwtAuthLab.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;

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

        //僅為了demo方便，將類別放在此
        public class LoginVM
        {
            public string Username { get; set; }
            public string Password { get; set; }
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
        /// <returns>【回傳說明】</returns>
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
            //先以登入輸入值到DB查到會員，這邊假的demo用
            Member member = new Member
            {
                MemberId = 1,
                Username = request.Username,
            };

            var jwt = _jwtHelper.GenerateJWT(member);

            BlackFilter._bannedList.Remove( member.MemberId.ToString() ); //移除黑名單

            return Ok(jwt);
        }

        [HttpGet]
        public IActionResult SignOut()
        {
            var memberId = User.Identity.Name;

            BlackFilter._bannedList.Add(memberId);
            return Ok($"登出了{memberId}，加進過濾黑名單");
        }

        [HttpGet]
        public IActionResult TestAuth()
        {
            return Ok($"驗證類型：{User.Identity.AuthenticationType}\n" +
                        $"通驗否：{User.Identity.IsAuthenticated}\n" +
                        $"你ID是 {User.Identity.Name}"
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
