
# JWT驗證 & Swagger  詳細教學Lab
## 前言
### 為何使用JWT驗證 
我有另外一個
[教cookie驗證的教學Lab](https://github.com/redgrandfa/CookieAuthenticationLab)。
由於cookie受同源政策影響，所以在前後端分離架構下，不適用cookie驗證；而token驗證可以填補這個需求。

token可中譯成**令牌/權杖**，這機制的理念，可想像成是：
1. 皇帝**發行**了令牌
2. 昭告各關卡/城門守衛，如何**檢驗**令牌真偽
3. 任何**攜帶**令牌的人，可以通行。


JSON Web Token(縮寫JWT)，顧名思義和**JSON字串**有關；是現在流行的，實踐token驗證的方案。

一些相關名詞如JWS、JWE可再自行去了解。

### 簡介JWT規格

依筆者的心得，簡單粗暴解釋，JWT由三個部分組成
1. header：
    標頭，註記用
2. payload：
    有效負荷，重要的資訊但非機密
3. signature
    簽章，檢驗真偽用

假設我用 `密(s)`表示將s加密，那JWT可想像成某三段文字用`.`隔開：

`密(header).密(payload).密(signature)`


而其中signature 是`密(header)`、`密(payload)`、`私鑰` 三者混成

signature其實是由header、payload、私鑰混成的，所以比對可判斷header、payload有沒有被竄改過


詳細可參考這篇文章
>[淺談 Authentication 中集：Token-based authentication](https://vicxu.medium.com/%E6%B7%BA%E8%AB%87-authentication-%E4%B8%AD%E9%9B%86-token-based-authentication-90139fbcb897)


### Lab大綱：(使用ASP.NET Core 5 )
0) 開專案
1) JWT
    - 發行JWT
    - 檢驗JWT
        - 授權教學
    - 攜帶JWT
    - 登入登出功能
        - (選擇性) 強化資安-黑名單Filter 

2) Swagger
    - 引入Swagger
    - 讓Swagger支援JWT
    - 配合XML文件註解

### 0 開專案
1. 範本選：ASP.NET Core Web 應用程式(Model-View-Controller)
2. 架構選：.NET 5.0
3. 驗證選：無

專案命名為JwtAuthLab

## 1 JWT
參考資料：
> [如何在 ASP.NET Core 3 使用 Token-based 身分驗證與授權 (JWT)](https://blog.miniasp.com/post/2019/12/16/How-to-use-JWT-token-based-auth-in-aspnet-core-31)

> [RFC 7519規格書](https://datatracker.ietf.org/doc/html/rfc7519#section-3) (主要可看第四章)



安裝Nuget套件：`Authentication.JwtBearer` (注意版本相依性)

### 1-1 發行JWT (皇帝發行令牌)
三步驟：
1. 產JWT用的helper
2. HttpPost的 API，呼叫第一步的helper取得JWT，回應前端
3. 前端呼叫第二步的API

#### 1-1-1 發行JWT的helper

新增Helpers資料夾，新增一個類別檔JwtHelper.cs，其中宣告GenerateToken方法，先把ClaimIdentity造出來：
```csharp
public class JwtHelper
{
    public string GenerateJWT(string username)
    {
        //(一)造ClaimsIdentity
        //實際應到資料庫查此username資料，看該有哪些claim
        //以下此僅demo
        var claims = new List<Claim>();

        claims.Add(new Claim(ClaimTypes.Name, username));

        //RFC 7519 規格書 第四章 定義了七個Registered Claim Names
        //Iss   Issuer  發行者
        //Sub   Subject         
        //Aud   Audience        
        //Exp   Expiration Time 過期時間
        //Nbf   Not Before      起效時間
        //Iat   Issued At       發行時間
        //Jti   JWT ID          unique identifier


        // 筆者對七個Registered Claim的測試：
        //claims.Add(new Claim(JwtRegisteredClaimNames.Iss, "在claim設定的")); //有效，但會被後面描述子裡的設定蓋過
        //claims.Add(new Claim(JwtRegisteredClaimNames.Sub, "在claim設定的")); //有效
        //claims.Add(new Claim(JwtRegisteredClaimNames.Aud, "在claim設定的")); //有效，但與後面描述子裡的 會組成陣列
        //claims.Add(new Claim(JwtRegisteredClaimNames.Exp, "1656666663")); //測試沒作用
        //claims.Add(new Claim(JwtRegisteredClaimNames.Nbf, "1656666662")); //測試沒作用
        //claims.Add(new Claim(JwtRegisteredClaimNames.Iat, "1656666661")); //測試沒作用
        //claims.Add(new Claim(JwtRegisteredClaimNames.Jti, "在claim設定的"));  //有效

        //結論：cliam這邊只需設定 Sub 和 Jti 這兩個
        claims.Add(new Claim(JwtRegisteredClaimNames.Sub, username));
        claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
        //註：有兩種命名空間可選，根據參考文章是選using System.IdentityModel.Tokens.Jwt;
        //    (這個命名空間含在 Nuget套件Authentication.JwtBearer 之中的)

        // 集合所有聲明描述的身分識別。這些聲明，將記在token的payload中
        var userClaimsIdentity = new ClaimsIdentity(claims);
    }
}
```
接下來，先到`appsettings.json`加入組態設定：
```json
{
  //...略
  "JwtSettings": {
    //發行者
    "Issuer": "JwtAuthLab", 
    //至少16字的私鑰，盡量中/英/符交雜難破解，此僅利於demo
    "SignKey": "qqqqwwwweeeerrrr" 
  }
}
```
JwtHelper類別注入組態

```csharp
public class JwtHelper
{
    private readonly IConfiguration configuration;

    public JwtHelper(IConfiguration configuration)
    {
        this.configuration = configuration;
    }

    public string GenerateJWT(string username){
        // ...
    }
}
```
GenerateJWT方法，做出tokenDescriptor物件後產生JWT：
```csharp
public string GenerateJWT(string username)
{
    //...方才寫到這
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


        //此屬性負責JWT的signature(JWT第三段)
        SigningCredentials = signingCredentials,
    };

    //(三) 造出JWT回傳
    var tokenHandler = new JwtSecurityTokenHandler();
    var securityToken = tokenHandler.CreateToken(tokenDescriptor);
    var serializeToken = tokenHandler.WriteToken(securityToken);

    return serializeToken;
}
```

到startup.cs檔

ConfigureServices方法中註冊JwtHelper進DI容器：
```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddControllersWithViews();
    services.AddScoped<JwtHelper>(); //註冊
}
```

#### 1-1-2 後端API
專案新增一個資料夾ApiControllers，其內心曾一個API控制器，命名為TokenController
1. 將Route規則更改
2. 建構式注入JwtHelper
3. 新增action命名為SignIn，並新增LoginVM這個類別以接收參數

```csharp
[Route("api/[controller]/[action]")] //1
[ApiController]
public class TokenController : ControllerBase
{
    private readonly JwtHelper _jwtHelper;

    //2
    public TokenController(JwtHelper jwtHelper)
    {
        _jwtHelper = jwtHelper;
    }
    //3
    [HttpPost]
    public IActionResult SignIn(LoginVM request)
    {
        return Ok( _jwtHelper.GenerateJWT(request.Username) );
    }

    //僅為了demo方便將類別放在此
    public class LoginVM 
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}
```

#### 1-1-3 前端呼叫API

//QQ
wwwroot/js 中新增Login.js檔，


_Layout.cshtml中 的head區段中引入cookie套件
```html
```
在_Layout.cshtml中，<body>區段的尾處引入Login.js 
```html
<script src="~/js/site.js" asp-append-version="true"></script>
<script src="https://cdn.jsdelivr.net/npm/js-cookie@rc/dist/js.cookie.min.js"></script>
<script src="~/js/Login.js"></script>
```

Login.js檔中，呼叫'/api/Token/SignIn'這支API，並把取得的JWT存入Cookie：
```javascript
let jwtNameInCookie = "JWT"
let jwtOptionInCookie = { expires: 14 };
//註：cookie的過期時間 應設定為和 jwt的過期時間 相同

signIn();
function signIn() {
    if (Cookies.get(jwtNameInCookie) != undefined) return

    let data = {
        username: 'testName',
        password: "123",
    }
    fetch('/api/Token/SignIn', {
        headers: {
            'Content-type': 'application/json',
        },
        method: 'POST',
        body: JSON.stringify(data),
    })
    .then(response => response.text())
    .then(jwt => {
        Cookies.set(jwtNameInCookie, jwt, jwtOptionInCookie);
    })
}
```


執行專案，到瀏覽器開發者工具中，查看呼叫Api的結果，以及JWT是否有存到cookie中。

將JWT字串複製，到 [jwt.io網站](https://jwt.io/) 貼上觀察，可見header、payload都可以逆運算出來

![image]()

*VERIFY SIGNATURE*區塊中輸入SignKey(appsettings.json中的)，再重貼一次JWT即可驗證Signature


註：如果想更了解產生JWT的細節，可以中斷點停在GenerateJWT方法return前，觀察**securityToken**這個物件中的屬性，比如：

- Header、Payload中的資訊，就是jwt.io推算出來的資訊
- EncodedHeader 、RawHeader 都是Header 編碼後的字串
- EncodedPayload、RawPayload都是Payload編碼後的字串

- SigningCredentials中
    - Algorithm屬性紀錄演算法是hamc-sha256(HS256)
    - Key屬性中找一下，可見SignKey記錄成byte陣列的形式
- RawSignature 是Signature編碼後的字串
- RawData 就是完整的JWT



### 1-2 檢驗JWT (昭告如何檢驗令牌真偽)
#### 1-2-1 設定JWT驗證機制 
到startup.cs檔

ConfigureServices方法中加入程式碼：
```csharp
services.AddScoped<JwtHelper>();

//設定token驗證機制
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.IncludeErrorDetails = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
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

```

Configure方法中中加入程式碼：
```csharp
app.UseAuthentication();//加
app.UseAuthorization(); 
```

#### 1-2-2 要求權限
將TokenController掛上`[Authorize]`
其中的SignIn掛上`[AllowAnonymous]`
新增一個action用來測試驗證效果：

```csharp
//...略
[Authorize] //加
public class TokenController : ControllerBase
{
    //...略
    [AllowAnonymous]//加
    public IActionResult SignIn(LoginVM request)
    {
        //...略
    }

    //...略
    // 加這個action
    public IActionResult TestAuth()
    {
        return Ok($"驗證類型：{User.Identity.AuthenticationType}\n" +
                    $"通驗否：{User.Identity.IsAuthenticated}\n" +
                    $"你是 {User.Identity.Name}"
                );
    }
}
```

於是TestAuth這支API要求攜帶著JWT才能訪問

如需要授權的教學，請參考筆者的[Cookie驗證Lab](https://github.com/redgrandfa/CookieAuthenticationLab)的第六小節，主要是`Role-based Authorization`與 `Policy-based Authorization` 的設定


### 1-3 攜帶JWT (帶著令牌過驗)
在Home/Index 中加一顆按鈕 去拜訪api/Token/TestAuth：

```html
<div class="text-center">
    @*做顆按鈕*@
    <button id="authApi">拜訪需要權限的的API</button>
</div>

@section Scripts{
    <script>
        document.querySelector('authApi').onclick = ()=>{
            fetch('api/Token/TestAuth' , {
                headers:{
                    Authorization: `Bearer ${Cookies.get(jwtNameInCookie)}`
                }
            })
        }
    </script>
}
```
執行專案，點擊按鈕會過關；若將cookie中的JWT刪除，則回應狀態401



### 1-4 登入登出功能

#### 1-4-1 製作登入登出UI的PartialView檔
在Views/Shared資料夾中加入空白檢視檔，命名為_LoginPartial.cshtml。

應判斷cookie中是否存著令牌，做出分支情況：
1. 登入狀態下，只能看到登出按鈕
2. 登出狀態下，只能看到登入按鈕

加入以下程式碼：

```html
@inject Microsoft.AspNetCore.Http.IHttpContextAccessor HttpContextAccessor;
@{
    //這兩種方式都無法確認是否登入中
    //bool a = User.Identity.IsAuthenticated;
    //bool b = HttpContextAccessor.HttpContext.User.Identity.IsAuthenticated;

    bool isAuthenticated = HttpContextAccessor.HttpContext.Request.Cookies.ContainsKey("JWT");
}

@if (isAuthenticated)
{
    <button id="sign-out" onclick="signOut()">登出</button>
}
else
{
    <label>帳號</label>
    <input id="username" value="XX" />
    <button id="sign-in" onclick="signIn()">登入</button>
}

```

由於有用到`IHttpContextAccessor`，須在startup.cs檔的ConfigureServices方法中註冊相依性：

```csharp
services.AddScoped<JwtHelper>();
services.AddHttpContextAccessor();// 加這行
```

#### 1-4-2 在導覽列 引入PartialView檔
Views/Shared資料夾中的_Layout.cshtml檔，引入此PartialView：

```html
<header>
    <nav ...>
        <div class="container">...
            ...
            <ul ...>
                ...
            </ul>
            <div id="login-partial">
                @await Html.PartialAsync("_LoginPartial")
            </div>
        </div>
    </nav>
</header>
```

#### 1-4-3 設定UI的點擊事件方法
wwwroot/js/Login.js中，調整成以下程式碼

```javascript
//signIn();
function signIn() {
    // ...略
    let data = {
        username: document.querySelector('#username').value,
        password: "123",
    }

    fetch('/api/Token/SignIn', {
        // ...略
    })
    .then(response => response.text())
    .then(jwt => {
        Cookies.set(jwtNameInCookie, jwt, jwtOptionInCookie);
        refreshLoginPartial() //加這行
    })
}

//登出方法
function signOut() {
    Cookies.remove(jwtNameInCookie, jwtOptionInCookie);
    refreshLoginPartial()
}

//登入登出後，都需要刷新UI
function refreshLoginPartial() {
    //重新載入一次Login的PartialView
    fetch('Home/LoginPartial')
        .then(response => response.text())
        .then(text => {
            document.querySelector('#login-partial').innerHTML = text
        })
}
```
而`refreshLoginPartial`方法中拜訪的API，須到HomeController中補個action如下：
```csharp
//再次渲染LoginPartial用
public IActionResult LoginPartial()
{
    return PartialView("_LoginPartial");  
}
```

執行專案測試，此時應能和登入登出按鈕互動，UI根據cookie裡存的JWT改變。

#### 1-4-4 (選擇性) 強化資安-黑名單Filter 
> 參考[](https://docs.microsoft.com/en-us/aspnet/core/mvc/controllers/filters?view=aspnetcore-5.0)
- 若有駭客取得某用戶某個JWT字串...

    即使用戶登出刪除了cookie裡的JWT，但JWT字串本身其實沒有失效，因為效期就寫在JWT字串身上!!(Payload裡記載的Expires、NotBefore)

    駭客仍然能用此JWT字串存取須權限的資源。

想實測效果的話，可自己扮演駭客把某JWT偷複製起來，然後在登出狀態下(即cookie已刪掉後)，在瀏覽器開發者工具寫個AJAX，攜帶JWT去拜訪TestAuth。


此處示範的解法，是在後端設計Filter來過濾黑名單。

新增Filters資料夾，並新增一個類別實作IAuthorizationFilter介面，補上程式碼如下：

```csharp
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

```

在startup.cs檔中，註冊此filter，則所有action執行前都會經過它篩選。
```csharp

public void ConfigureServices(IServiceCollection services)
{
    //...前略
    //註冊Filter
    services.AddControllers(options =>
    {
        options.Filters.Add(new BlackFilter());
    });
}
```

可執行專案測試，確認：
用bad這個名稱登入，拜訪需權限的api會失敗(回應403)


##### 登出配合Filter
TokenController中設計API命名為SignOut，讓前端呼叫時能把用戶加入黑名單

後端：
```csharp
public IActionResult SignOut()
{
    var name = User.Claims
        .FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;

    BlackFilter._bannedList.Add(name);
    return Ok($"登出了{name}，加進過濾名單");
}
```

前端： (修改Login.js中的登出方法)
```javascript
//登出方法
function signOut() {
    fetch('/api/Token/SignOut', {
        headers: {
            Authorization: `Bearer ${Cookies.get(jwtNameInCookie)}`
        },
    })

    Cookies.remove(jwtNameInCookie, jwtOptionInCookie);
    refreshLoginPartial()
}
```

##### 登入配合Filter
當登入時，要在SignIn API中移除黑名單。
```csharp
//進此action之前，會先進入BlackFilter
//但因為未攜帶JWT，故無妨
public IActionResult SignIn(LoginVM request)
{
    BlackFilter._bannedList.Remove(request.Username);
    return Ok(_jwtHelper.GenerateJWT(request.Username));
}
```

到此完成，可以再自行扮演駭客測試效果。

另外有兩個小提醒：

1. 示範的黑名單記錄在變數，會受到應用程式的生命週期影響，應該記錄在**資料庫**中。

2. 用戶可能登出之後，下次登入已間隔長時間(甚至一去不回)；此用戶再次登入前，一直存在於黑名單內，而當產生過的JWT失效後，已經沒必要再記錄著黑名單。

    可以寫個背景排程來定期清理黑名單；清理的判斷依據可以是用戶最後一次登入的時間+兩週，因為JWT已經超過發行時規定的有效期間，沒必要再提防了。

---




### 三個token可能實用的API

在TokenController裡加入以下程式碼，分別是：
1. 取得所有**Claims**
2. 取得JWT七種已註冊claim中的**Sub**
3. 取得JWT七種已註冊claim中的**Jti**

```csharp
//三個實用的API
public IActionResult GetClaims()
{
    return Ok(User.Claims.Select(c => new { c.Type, c.Value }));
}

public IActionResult GetSub()
{
    //var sub = User.Claims.FirstOrDefault(p => p.Type == JwtRegisteredClaimNames.Sub); //實際上不存在
    var sub = User.Claims.FirstOrDefault(p => p.Type == 
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");
    return Ok(sub?.Value);
}

public IActionResult GetJti()
{
    var jti = User.Claims.FirstOrDefault(p => p.Type == JwtRegisteredClaimNames.Jti);
    return Ok(jti?.Value);
}

```
(這三個API待會可配合swagger的路由教學。)

## 2 Swagger
參考資料：
> [(微軟文件)Swashbuckle 與 ASP.NET Core 使用者入門](https://docs.microsoft.com/zh-tw/aspnet/core/tutorials/getting-started-with-swashbuckle?view=aspnetcore-5.0&tabs=visual-studio#xml-comments)


安裝Nuget套件：`Swashbuckle.AspNetCore` (注意版本相依性)

### 2-1 MVC專案引入Swagger
(建議開一個WebAPI專案來觀察，假設專案隨便命名為Q，startup中可看到swagger相關的設定，可複製來修改)

在startup.cs檔中，加入以下程式碼：

```csharp
public void ConfigureServices(IServiceCollection services){
    // ...前略
    // Register the Swagger generator, defining 1 or more Swagger documents
    services.AddSwaggerGen(c =>
    {
        c.SwaggerDoc("v1", new OpenApiInfo { 
            Title = "Swagger首頁標題", 
            Version = "v1" 
            //還有幾個屬性可以設定
        });
    });
}

public void Configure(IApplicationBuilder app)
{
    if (env.IsDevelopment())
    {
        app.UseDeveloperExceptionPage();
        // Enable middleware to serve generated Swagger as a JSON endpoint.
        app.UseSwagger();

        // Enable middleware to serve swagger-ui (HTML, JS, CSS, etc.)
        app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "定義名稱 v1"));
    }
    //...略
}
```

執行專案測試，確認網址輸入 `~/swagger`後，可到swagger首頁。

註：此時大致上會出現 Fetch error undefined ...的錯誤；這是因為，本來API如果是以GET方式拜訪，可以省略`[HttpGet]`，但搭配swagger就必須要將所有的API全都明確掛上`[HttpXXX]`才能解決。

所以補上：
```csharp
[HttpGet]
public IActionResult SignOut(){...}

[HttpGet]
public IActionResult TestAuth(){...}

[HttpGet]
public IActionResult GetClaims(){...}

[HttpGet]
public IActionResult GetSub(){...}

[HttpGet]
public IActionResult GetJti(){...}
```


#### 2-1-1 (選擇性) 路由設定
##### swagger首頁網址
swagger首頁預設的網址是：`~/swagger/index.html`
所以每次執行專案都要輸入網址，才能查看swagger，不免覺得麻煩。

可以如下設定swagger的路由前綴，使網址變成：`~/index.html`，那麼專案剛開啟就是swagger首頁：
```csharp
app.UseSwaggerUI(c => {
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "定義名稱 v1");
    c.RoutePrefix = string.Empty; //加此句
});
```
##### api的四種路由設定
第一種就是Controller內的整體路由設定：

```csharp
[Route("api/[controller]/[action]")] //路由
[ApiController]
[Authorize]
public class TokenController : ControllerBase
```

用三個API來測試其他三種路由設定如下：
```csharp
[HttpGet("claims")]
public IActionResult GetClaims(){...}

[HttpGet("/sub")]
public IActionResult GetSub(){...}

[HttpGet("~/jti")]
public IActionResult GetJti(){...}
```

執行專案，在swagger就可以直接看見端點。
整理一下效果：
```csharp
[HttpGet("claims")] 
//  /api/Token/GetClaims/claims  
//  controller路由規則/指定路徑
//  註：若搭配Api控制器預設的路由規則 api/[controller]，就比較合理了。

[HttpGet("/sub")]
//  /sub
//  網站根目錄/指定路徑

[HttpGet("~/jti")]
//  /jti
//  網站根目錄/指定路徑
```




此時，在swagger測試各API的執行的話：
- 只有SignIn這支API可以得到回應200
- 其他所有要求Authorize的API都會回應401

這很合理，畢竟沒攜帶JWT。所以再來要讓Swagger支援JWT機制

---
## 2-2 讓Swagger支援JWT

參考這篇文章：
> [使用 Swashbuckle 請求時加入 【JWT】](https://clarklin.gitlab.io/2021/06/13/asp-dotnet-core-api-document-using-jwt/)

基本上照著複製貼上，執行專案，依文章內的教學操作swagger UI。


```csharp
services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { 
        Title = "Swagger首頁標題", 
        Version = "v1" 
        //還有幾個屬性可以設定
    });
    
    // 以下複製貼上
    // swagger 加入 jwt 支援
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
    {
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,.Http, //這裡要修改
        Scheme = "Bearer",
        BearerFormat = "JWT",
        Description = "JWT Authorization header using the Bearer scheme."
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement()
    {
        { new OpenApiSecurityScheme(){ }, new List<string>() }
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
});
```



### 2-3 (選擇性) XML文件註解
這邊都是照著微軟文件的教學。

#### 2-3-1 啟用XML 註解
如下編輯專案的 .csproj檔
```xml
<PropertyGroup>
    <TargetFramework>net5.0</TargetFramework>
	<GenerateDocumentationFile>true</GenerateDocumentationFile>
</PropertyGroup>
```

#### 2-3-2 設定 Swagger 以使用所產生的 XML 檔案

```csharp
services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { 
        //...略
    });

    // Set the comments path for the Swagger JSON and UI.
    var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    c.IncludeXmlComments(xmlPath);
});
```

選一個API增加XML文件註解：
(主要有四種：標題、參數、remark、reponseType)

```csharp
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
    return _jwtHelper.GenerateJWT(request.Username);
    // 注意 回傳型別改成了ActionResult<string>，
}
```

執行專案去觀察UI。



#### 2-3-3 自訂CSS
如果想自訂CSS，處理swagger的UI，如下注入CSS檔：
```csharp
app.UseSwaggerUI(options =>
{
    options.InjectStylesheet("/swagger-ui/custom.css");
});
```

---
## (選擇性) Logger機制
可參考筆者的[Cookie驗證教學Lab](https://github.com/redgrandfa/CookieAuthenticationLab)第7節的內容
