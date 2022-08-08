let jwtNameInCookie = "JWT"
let jwtOptionInCookie = { expires: 14 };
//註：cookie的過期時間 應設定為和 jwt的過期時間 相同

//signIn();
refreshLoginPartial() //因為瀏覽器可能有快取的問題，開場最好再去更新一下(不然就得要手動重新整理)

function signIn() {
    if (Cookies.get(jwtNameInCookie) != undefined) return

    let data = {
        username: document.querySelector('#username').value,
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
        refreshLoginPartial()
    })
}

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

//登入登出後，都需要刷新UI
function refreshLoginPartial() {
    //重新載入一次Login的PartialView
    fetch('/Home/LoginPartial')
        .then(response => response.text())
        .then(text => {
            document.querySelector('#login-partial').innerHTML = text
        })
}