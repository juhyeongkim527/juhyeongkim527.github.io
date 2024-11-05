---
title: '[Dreamhack] pathtraversal'
description: Dreamhack [Wargame] - pathtraversal 
author: juhyeongkim
date: 2024-11-05 17:50:00 +0900
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

[문제 링크](https://dreamhack.io/wargame/challenges/12)

{% raw %}

## Source code

```py
#!/usr/bin/python3
from flask import Flask, request, render_template, abort
from functools import wraps
import requests
import os
import json

users = {
    '0': {
        'userid': 'guest',
        'level': 1,
        'password': 'guest'
    },
    '1': {
        'userid': 'admin',
        'level': 9999,
        'password': 'admin'
    }
}


def internal_api(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if request.remote_addr == '127.0.0.1':
            return func(*args, **kwargs)
        else:
            abort(401)
    return decorated_view


app = Flask(__name__)
app.secret_key = os.urandom(32)
API_HOST = 'http://127.0.0.1:8000'

try:
    FLAG = open('./flag.txt', 'r').read()  # Flag is here!!
except:
    FLAG = '[**FLAG**]'


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/get_info', methods=['GET', 'POST'])
def get_info():
    if request.method == 'GET':
        return render_template('get_info.html')
    elif request.method == 'POST':
        userid = request.form.get('userid', '')
        info = requests.get(f'{API_HOST}/api/user/{userid}').text
        return render_template('get_info.html', info=info)


@app.route('/api')
@internal_api
def api():
    return '/user/<uid>, /flag'


@app.route('/api/user/<uid>')
@internal_api
def get_flag(uid):
    try:
        info = users[uid]
    except:
        info = {}
    return json.dumps(info)


@app.route('/api/flag')
@internal_api
def flag():
    return FLAG


application = app  # app.run(host='0.0.0.0', port=8000)
# Dockerfile
#     ENTRYPOINT ["uwsgi", "--socket", "0.0.0.0:8000", "--protocol=http", "--threads", "4", "--wsgi-file", "app.py"]
```

이번 문제의 소스 코드는 위와 같다. 코드를 하나씩 분석해보며 flag를 찾을 수 있는 방법을 살펴보자.

## 웹 서비스 분석

### internal_api(func)

```py
def internal_api(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if request.remote_addr == '127.0.0.1':
            return func(*args, **kwargs)
        else:
            abort(401)
    return decorated_view
```

해당 함수는 인자로 받은 `func`를 `if` 조건에 따라 리턴해주는 Decorator 함수를 포함하고 있다.

`request`를 보내는 클라이언트의 IP 주소가 로컬 호스트인 `'127.0.0.1'`인 경우 `func`를 리턴하는 데코레이터 함수를 만들고,

로컬 호스트가 아닌 경우 `abort(401)`를 통해 **401 코드 : Unauthorized**를 리턴한다.

정리하면, `internal_api(func)` 함수는 `request`를 보내는 클라이언트의 IP 주소가 로컬호스트이면 그대로 함수를 리턴하고, 아닌 경우 401 코드를 리턴하는 함수라고 생각하면 된다.

내부 로컬호스트의 `request`에 의해서만 flag에 접근할 수 있도록 제한하는 내부 API로 보인다.

<br>

### 엔드 포인트 : **/get_info**

```py
@app.route('/get_info', methods=['GET', 'POST'])
def get_info():
    if request.method == 'GET':
        return render_template('get_info.html')
    elif request.method == 'POST':
        userid = request.form.get('userid', '')
        info = requests.get(f'{API_HOST}/api/user/{userid}').text
        return render_template('get_info.html', info=info)
```

`/get_info` 엔드 포인트에서는 GET, POST 요청을 처리한다.

GET 요청이 오는 경우 아래와 같은 페이지를 렌더링한다.

![alt text](assets/img/pathtraversal/image_1.png)

POST 요청이 오는 경우 `userid` 필드에서 form을 통해 입력한 값을 가져온 후 아래 코드를 통해 GET 요청을 보낸다.

```py
info = requests.get(f'{API_HOST}/api/user/{userid}').text
```

`/api/user/<form에서 입력 받은 값>` 주소에 GET 요청을 보낸 후 응답을 `info`에 저장하는데, 여기서 GET 요청을 보내는 주체는 웹 서버인 **로컬호스트**이기 때문에, 

`userid`에 **Path Traversal** 취약점을 통해 상대경로로 flag가 존재하는 디렉토리로 이동해서 flag 값을 읽어올 수 있을 것이다.

flag 파일은 어디 위치할지 계속 살펴보자.

<br>

### 엔드 포인트 : **/api, /api/user/&lt;uid&gt;**

```py
@app.route('/api')
@internal_api
def api():
    return '/user/<uid>, /flag'


@app.route('/api/user/<uid>')
@internal_api
def get_flag(uid):
    try:
        info = users[uid]
    except:
        info = {}
    return json.dumps(info)
```

두 엔드 포인트 모두 `@internal_api` 데코레이터를 통해, 위에서 살펴보았듯이 클라이언트의 IP가 로컬호스트일 때만 해당 엔드 포인트에 접근할 수 있도록 되어있다.

`/api` 엔드 포인트에 접근하면, 그냥 **"/user/&lt;uid&gt;, /flag"** 문자열을 리턴한다.

내부 API로 접근할 수 있는 엔드 포인트가 뭐가 있는지 보여주는 기능을 하는 것 같다.

`/api/user/<uid>` 엔드 포인트는 `<uid>` 위치에 오는 값을 동적 변수로 `uid`에 저장하여 `users`에 접근한 후 `info`를 리턴해준다.

근데 잘 보면, `users`에 key 값으로 접근하기 때문에 `uid`에는 `guest`, `admin` 문자열이 아닌 `0` 또는 `1`이 들어가야 한다.

그래서 뭔가 브라우저에서 이를 변환해주는 과정이 들어가있는 것 같은데, 이것 때문에 브라우저를 통해 **Path Traversal** 취약점을 활용할 수 없다.

이건 Exploit 파트에서 더 자세히 살펴보자.

<br>

### 엔드 포인트 : **/api/flag**

```py
@app.route('/api/flag')
@internal_api
def flag():
    return FLAG
```

flag가 존재하는 엔드 포인트이다. 결론적으로 해당 엔드 포인트에 `/get_info` 엔드 포인트를 통해 접근하여 `FLAG`를 리턴받아오면 될 것이라는 것을 알 수 있다.

<br>

## Exploit

`/get_info` 엔드 포인트에서 내부 API(로컬호스트의 `request`)를 통해 **Path Traversal** 취약점을 이용할 수 있다고 하였다.

따라서 form 으로 입력 받는 `uid` 값에 `../flag`를 입력해주면 `/api/user/../flag`에 GET 요청을 보낸 후 응답을 받아오기 때문에, `/api/flag`에 접근하여 `FLAG`를 리턴해올 수 있게 된다.

처음에 어쩌피 `/get_info`에서 웹 서버의 로컬호스트로 `/api/flag`에 GET 요청을 보낼 수 있으니, 브라우저를 통해서 바로 `/get_info`에 접근하여 `../flag`를 입력해주면 되지 않을까라고 생각했었다.

근데 이렇게 하니까 아래처럼 `info`에 아무 값도 리턴되지 않았다.

![alt text](assets/img/pathtraversal/image_2.png)

브라우저에서 form에 값을 입력하고 보낼 때를 순간적으로 파악해보면, `guest`를 입력하면 `0`으로 변환, `admin`을 입력하면 `1`으로 변환, `../flag`를 입력하면 `undefined`로 변환되어 form에 값이 전달된다.

```py
users = {
    '0': {
        'userid': 'guest',
        'level': 1,
        'password': 'guest'
    },
    '1': {
        'userid': 'admin',
        'level': 9999,
        'password': 'admin'
    }
}

...

@app.route('/api/user/<uid>')
@internal_api
def get_flag(uid):
    try:
        info = users[uid]
    except:
        info = {}
    return json.dumps(info)
```

이 부분을 잘 보면, `info = users[uid]`를 통해 `info` 값을 가져오는데 `uid`에 입력된 값이 `users`에 존재하지 않으면 `{}`을 리턴한다.

`uid`는 `users`의 key 값이므로 `0`, `1`만 존재할 수 있기 때문에 이외 값이 들어오면 전부 `except`에 걸리게 된다.

따라서 `guest`와 `admin`의 경우 `key` 값이 각각 `'0'`, `'1'` 인 것을 보아, 브라우저에서 접근한 `/get_info` 엔드 포인트에서는 미리 form에 입력한 값을 변환하여 `userid` 값에 대입해주는 것이라는 예상을 할 수 있다.

따라서 `../flag`를 입력해도`userid` 값에 그대로 전달되지 않기 때문에 브라우저에서는 **Path Traversal** 취약점을 적용할 수 없는 것이다.

따라서 내부 API로 접근할 수 있는 취약점이 존재하더라도 결국 브라우저를 통해서는 `/api/flag` 엔드 포인트에 요청을 보낼 수 없게 된다.

어떤 원리로 그렇게 되는지는 모르겠지만, 일단 그럼 브라우저를 통해서가 아니라 바로 Request를 보내는 방법으로 **Burp Suite**와 **`request` 모듈**을 통한 방법을 살펴보자.

<br>

### 1. Burp Suite

Burp Suite를 통해 `/get_info` 엔드 포인트에 접근하여 Request를 받아온 후 `userid = ../flag`로 POST 요청을 보내서 응답값을 받아오면 `FLAG` 값을 확인할 수 있다.

참고로, Proxy 탭에서 **Intercept on**을 켜두고 프록시 브라우저에서 페이지를 이동하면 잘 안된다.

따라서 **Intercept off** 상태에서 Request를 받아올 페이지에 접속한 후, on으로 켜서 Request를 받아와야 한다.

위 과정대로 프록시 브라우저에서 `/get_info` 엔드 포인트에 접근한 후 `../flag`를 form에 입력해주면 아래와 같이 Request를 받아올 수 있다.

![alt text](assets/img/pathtraversal/image_3.png)

여기서도 Request를 살펴보면, 브라우저를 통해 `../flag`를 전달하면 `userid = undefined`로 POST 요청이 전달되는 것을 확인할 수 있다.

확인해봤을 때, `guest`, `admin`으로 보내면 `0`, `1`로 전달된다.

그럼 이제 브라우저를 통해서가 아니라 **Repeater** 탭에서 직접 `userid=../flag`로 세팅하여 POST 요청을 보내면 **Path Traversal** 취약점을 발생시킬 수 있을 것이다.

![alt text](assets/img/pathtraversal/image_4.png)

위와 같이 조작하여 보내면 `<pre>` 태그 안에 `FLAG` 값이 출력되는 것을 확인할 수 있다.

<br>

### 2. requests 모듈 사용

```py
import requests

url = "http://host3.dreamhack.games:10603/get_info"
data = {"userid" : "../flag"} 
headers = {
}

response = requests.post(url, headers=headers, data=data)
print(response.text)
```

브라우저를 통해서가 아닌, `requests` 모듈을 통해 직접 POST 요청을 위와 같이 보내면, `response.text`에 전달된 FLAG 값을 읽어올 수 있다.

![alt text](assets/img/pathtraversal/image_5.png)

{% endraw %}