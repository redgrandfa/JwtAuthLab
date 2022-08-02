using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuthLab.Helpers
{
    public class JwtHelper
    {
        private readonly IConfiguration configuration;

        public JwtHelper(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        //模擬DB中的Member資料。僅為了demo方便，將類別放在此
        public class Member
        {
            public int MemberId { get; set; }
            public string Username { get; set; }
        }

        public string GenerateJWT(Member member)
        {   
            //(一)造ClaimsIdentity
            //實際應到資料庫查此username資料，看該有哪些claim
            //以下此僅demo
            var claims = new List<Claim>();
            claims.Add(new Claim(ClaimTypes.Name, member.MemberId.ToString()));

            //RFC 7519 規格書 第四章 定義了七個Registered Claim Names
            //Iss   Issuer          發行者
            //Sub   Subject         
            //Aud   Audience        接收者     
            //Exp   Expiration Time 過期時間
            //Nbf   Not Before      起效時間
            //Iat   Issued At       發行時間
            //Jti   JWT ID          unique identifier


            // 筆者對七個Registered Claim的測試：
            //claims.Add(new Claim(JwtRegisteredClaimNames.Iss, "在claim設定的")); //有效，但會被後面描述子裡的設定蓋過
            //claims.Add(new Claim(JwtRegisteredClaimNames.Sub, "在claim設定的")); //有效
            //claims.Add(new Claim(JwtRegisteredClaimNames.Aud, "在claim設定的")); //有效，與後面描述子裡的 會組成陣列
            //claims.Add(new Claim(JwtRegisteredClaimNames.Exp, "1656666663")); //測試沒作用
            //claims.Add(new Claim(JwtRegisteredClaimNames.Nbf, "1656666662")); //測試沒作用
            //claims.Add(new Claim(JwtRegisteredClaimNames.Iat, "1656666661")); //測試沒作用
            //claims.Add(new Claim(JwtRegisteredClaimNames.Jti, "在claim設定的"));  //有效

            //結論：cliam這邊只需設定 Sub 和 Jti 這兩個
            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, member.Username));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            //註：有兩種命名空間可選，根據參考文章是選using System.IdentityModel.Tokens.Jwt;
            //    (這個命名空間含在 Nuget套件Authentication.JwtBearer 之中的)

            // 集合所有聲明描述的身分識別。這些聲明，將記在token的payload中
            var userClaimsIdentity = new ClaimsIdentity(claims);


            //(二)準備token的descriptor(譯：描述子)
            var issuer = configuration.GetValue<string>("JwtSettings:Issuer");
            var signKey = configuration.GetValue<string>("JwtSettings:SignKey"); //私鑰不可外流

            // 對稱式加密後的金鑰，產 JWT 的signature(簽章)要用
            var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signKey));
            
            // 用來產生signature 的密碼編譯演算法
            var signingCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256Signature);
            // 註：HmacSha256 有要求必須要大於 128 bits，所以才說signKey 至少要 16 字元以上


            // 描述token的相關設定的物件
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                // 七個Registered Claim中，claim區有四個設定有效，這四個在此的測試：
                //Issuer = "在Descriptor設定的",  //會覆蓋claim 設定的Iss
                //Subject 是ClaimsIdentity型別
                //Audience = "在Descriptor設定的",  //會與claim的設定併存組成陣列
                //沒有Jti 屬性可以設定

                //結論：cliam區設定兩個，在此設定五個：
                Issuer = issuer,
                Subject = userClaimsIdentity, //這些聲明，將記在token的payload中
                Expires = DateTime.UtcNow.AddDays(14),
                //NotBefore = DateTime.UtcNow,
                //IssuedAt = DateTime.UtcNow,
                    //註：三個時間都有預設值：Nbf與Iat是UtcNow，Exp是UtcNow再加3600(秒)


                //此屬性負責JWT的第三段文字(signature)
                SigningCredentials = signingCredentials,
            };

            //(三) 造出JWT回傳
            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.CreateToken(tokenDescriptor);
            //可加中斷點觀察：header、payload => 加密後的兩者  + RawSignature => RawData  用.隔開

            var serializeToken = tokenHandler.WriteToken(securityToken);
            //可加中斷點觀察：此字串值會是 RawData

            return serializeToken;
        }
    }
}
