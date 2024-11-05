---
title: '[Dreamhack] command-injection-1'
description: Dremhack [Wargame] - command-injection-1
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

[문제 링크](https://dreamhack.io/wargame/challenges/44)

## 문제 목표 및 기능 요약

이 문제의 목표는 서버 내부에 있는 `flag.py` 파일을 `cat` 명령어를 통해 읽어내는 것이다. 아래는 `flag.py`의 내용이다.

```py
FLAG = 'DH{[REDACTED]}'
```

사이트에 접속해보면 아래와 같이 특정 Host에 `ping` 패킷을 보내는 기능을 제공하고 있음을 확인할 수 있다.

<img width="535" alt="image" src="https://github.com/user-attachments/assets/535b32a6-052c-40f4-b624-b821a0c5020d">

<br>

## 웹 서비스 분석

### 엔드 포인트 : `/ping`

```py
@APP.route('/ping', methods=['GET', 'POST'])
def ping():
    if request.method == 'POST':
        host = request.form.get('host')
        cmd = f'ping -c 3 "{host}"'
        try:
            output = subprocess.check_output(['/bin/sh', '-c', cmd], timeout=5)
            return render_template('ping_result.html', data=output.decode('utf-8'))
        except subprocess.TimeoutExpired:
            return render_template('ping_result.html', data='Timeout !')
        except subprocess.CalledProcessError:
            return render_template('ping_result.html', data=f'an error occurred while executing the command. -> {cmd}')

    return render_template('ping.html')
```

위 코드를 살펴보면 해당 엔드포인트에서 `GET` 메소드를 요청받았을 때에는 간단히 `ping.html` 페이지를 랜더링해준다.

`POST` 요청을 받았을 때를 살펴보면 `form`에서 입력 받은 `host` 값을 저장하고, `cmd = f'ping -c 3 "{host}"'`를 통해 입력 받은 `host`를 `cmd`에 대입한다. (`""`로 감싸져있는 것을 주의하자.)

그런데 `output = subprocess.check_output(['/bin/sh', '-c', cmd], timeout=5)` 코드를 보면, 시스템 함수를 사용할 때 `/bin/sh`에 전달될 명령어로 `cmd`를 사용하는 것을 볼 수 있다.

여기서 `cmd` 값에 메타 문자가 포함되어있는지, 악성 스크립트가 실행될 명령어가 포함되어있는지 확인하지 않기 때문에 **Command Injection** 취약점이 발생하게 된다.

`output`이 존재하면, `ping_result.html`에 `data` 인자를 해당 값으로 보낸다.

그런데 `ping_result.html`에서는 아래와 같이 전달 받은 인자값을 출력해주기 때문에, `output`에 `ping`의 결과뿐만 아니라 `ls` 또는 `cat flag.py` 명령어의 실행 결과값이 들어간다면 플래그의 위치를 찾고 플래그의 내용을 출력할 수 있을 것이다.

{% raw %}
```html
{% if data %}
  <pre>{{ data }}</pre>
{% endif %}
```
{% endraw %}

그런데 아래를 보면 명령어 실행 시간이 인자로 설정한 5초를 초과하여 `subprocess.TimeoutExpired` exception이 발생하거나,

명령어 실행 중 오류가 발생하여 `subprocess.CalledProcessError` exception이 발생하면 `data`에 오류 메시지가 전달된다.

그래서 처음에는 `ping`에 올바르지 않은 IP나 공백을 전달해서 `ping` 패킷을 보낼 때 오류가 발생하면, 뒤의 `ls`나 `cat flag.py`의 결과도 전달되지 않을 것이라고 생각했다.

그런데 `subprocess.CalledProcessError`는 `subprocess` 명령어를 순차적으로 실행하다가 도중에 에러가 발생해도, **마지막 명령어에서만 에러가 발생하지 않으면 exception이 발생하지 않는다.**

따라서, `ping`에는 공백을 전달해줘도 되기 때문에 이를 신경쓸 필요 없이 **마지막 명령어에서만 에러가 발생하지 않도록 하면 된다.**

<br>

#### subprocess.check_output 함수(Information)

이 함수는 서브 프로세스를 실행하고, 서브 프로세스의 실행 결과로 나온 출력 문자열을 파이썬의 변수에 담아 사용하고 싶을 때 사용하는 함수이다.

만약 이 함수의 **마지막 명령어가 비정상 종료되면 `CalledProcessError` exception을 발생시킨다.**

<br>

## Exploit

그럼 실제로 `/ping` 엔드 포인트의 폼에서, `cmd`에 저장될 `host` 값을 어떻게 전달할지 익스플로잇 설계를 해보자.

조건은 아래와 같다.

1. `subprocess`의 명령어 실행에서 에러가 발생하면 안되기 때문에, 마지막 명령어가 정상적으로 실행되어야 한다.

2. `flag.py` 파일의 위치를 찾기 위해 `ls` 명령어를 추가하여 파일의 위치를 찾아야한다.

3. `ls` 명령어로 위치를 찾았다면, `cat` 명령어를 추가하여 플래그를 출력해야한다.

따라서, 처음에 `"; ls #`을 전달해주었는데 아래와 같이 **"요청한 형식과 일치시키세요.""** 라는 메시지가 출력되었다.

<img width="511" alt="image" src="https://github.com/user-attachments/assets/e0a9d3e5-4761-48a1-a62b-ff0601a4f20d">

---

참고로 `#`은 쉘 명령어에서 주석을 뜻하는 것으로, `app.py`에서 `{cmd}`가 `""`로 감싸져있기 때문에 마지막 `"`을 주석처리하기 위함이다. 

`#` 대신 `;"`로 바꾸어 마지막 명령어를 `ls`가 아닌 `""`로 바꾸면, 마지막에 빈 명령어가 실행되는데 이는 쉘에서 에러를 발생시키기 때문에 `CalledProcessError` 익셉션이 발생한다. 

---

다시 돌아와서 앞의 이미지에서 입력 형식 문제를 해결해보자.

폼의 입력 형식이 지정되어 있는 것 같아서, `ping.html`을 살펴보니 아래와 같이 `pattern="[A-Za-z0-9.]{5,20}"`을 통해 폼의 입력 형식이 지정되어 있었다.

{% raw %}
```html
{% extends "base.html" %}
{% block title %}ping{% endblock %}

{% block head %}
  {{ super() }}
{% endblock %}

{% block content %}
<h1>Let's ping your host</h1><br/>
<form method="POST">
  <div class="row">
    <div class="col-md-6 form-group">
      <label for="Host">Host</label>
      <input type="text" class="form-control" id="Host" placeholder="8.8.8.8" name="host" pattern="[A-Za-z0-9.]{5,20}" required>
    </div>
  </div>

  <button type="submit" class="btn btn-default">Ping!</button>
</form>
{% endblock %}
```
{% endraw %}

따라서, 입력 형식인 `알파벳 대문자 || 알파벳 소문자 || 0~9 || . && 5 ~ 20자`를 지키며 어떻게 입력할지 생각해봐야한다.

처음에 어떻게 해야하는지 잘 판단하기 힘들어서 풀이를 보았는데, 오히려 매우 간단하게 개발자 도구 탭에 들어가서 `pattern="[A-Za-z0-9.]{5,20}"`을 지워준 후 폼을 입력해주면 위 명령어가 잘 전달되었다.

개발자 도구 탭에서 `HTML` 태그 내의 `pattern` 속성을 지워줘도 되는 이유는, **HTML 태그 속성은 서버 단이 아닌 클라이언트 단에서 검증이 일어나기 때문이다.**

따라서, 클라이언트 단에서 `pattern` 속성을 지워서 검증을 없애면 필터링을 우회할 수 있고, 서버 단에서는 이를 검증하지 않기 때문에 원하는 스크립트를 전달할 수 있게 되는 것이다.

**참고로, _프록시 툴_ 이나 _Burp Suite_ 을 통해서도 `pattern`을 우회할 수 있다고 하는데 이는 다음에 더 공부해보고 풀어보자.**

<img width="345" alt="image" src="https://github.com/user-attachments/assets/ac031ace-513c-4531-a62a-beaefed496a8">

<img width="357" alt="image" src="https://github.com/user-attachments/assets/3cca4dfa-9c1b-40b3-bf14-6f24da7aa0e8">

<img width="663" alt="image" src="https://github.com/user-attachments/assets/712bd798-f84d-4f94-9222-6754efd3676c">

`ls` 명령어를 수행했을 때, `flag.py`가 존재하는 것을 확인하였기 때문에 현재 디렉토리 내에 플래그 파일이 존재하는 것을 알 수 있었다.

참고로 만약 `flag.py`가 존재하지 않았다면 상대 경로나 절대 경로를 통해 다시 탐색해야 했을 것이다.

그럼 이제, `"; cat flag.py #`를 전달해주면 아래와 같이 플래그를 획득할 수 있을 것이다. 

참고로 `; cat "flag.py`를 전달해주면 마지막 명령어가 `cat "flag.py"`가 되고 `cat`은 `""`로 감싸져있는 경우 문자열로 해석하기 때문에 똑같은 명령이 실행된다.

<img width="993" alt="image" src="https://github.com/user-attachments/assets/620fb17c-4a3f-4b41-b258-8c8593e6c9fe">

---

그리고 위에서 `ping`에 빈 문자열을 전달해주면 에러가 발생하는 것과, 마지막 명령어가 공백이면 에러가 발생하는 것을 한번 테스트해보자.

먼저, `ping`에 공백을 전달하기 위해서는 `pattern`과 `required` 속성을 제거하여 아무 값을 입력하지 않고 폼을 전달하면 아래와 같이 에러가 발생하는 것을 확인할 수 있다.

<img width="666" alt="image" src="https://github.com/user-attachments/assets/c63498ec-1f00-43d3-bf91-9197cbb0fc80">

그리고 마지막 명령어가 공백인 경우는, `"; ls; "`를 전달해주면 `ping -c 3 ""; ls; ""`가 수행된다. 

이 경우 아래와 같이 에러가 발생하는 것을 통해 명령어가 공백인 경우 쉘에서 에러가 발생하는 것을 확인할 수 있다.

<img width="993" alt="image" src="https://github.com/user-attachments/assets/72a493dc-110e-42cf-8fd1-bb0e43369675">

이렇게 시스템 함수를 실행할 때, 이용자의 입력이 인자에 추가되면 Command Injection 취약점이 발생할 수 있다.

따라서, 이러한 경우 이용자의 입력을 브라우저 단이 아닌, 꼭 서버 단에서 필터링하여 취약점을 막아야 함을 기억하자.