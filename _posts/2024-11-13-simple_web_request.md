---
title: '[Dreamhack] simple-web-request'
description: 'Dreamhack [Wargame] - simple-web-request'
author: juhyeongkim
date: 2024-11-13 03:15:00 +0900
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

[문제 링크](https://dreamhack.io/wargame/challenges/830)

{% raw %}

## Source code

```py
#!/usr/bin/python3
import os
from flask import Flask, request, render_template, redirect, url_for
import sys

app = Flask(__name__)

try: 
    # flag is here!
    FLAG = open("./flag.txt", "r").read()      
except:
    FLAG = "[**FLAG**]"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/step1", methods=["GET", "POST"])
def step1():

    #### 풀이와 관계없는 치팅 방지 코드
    global step1_num
    step1_num = int.from_bytes(os.urandom(16), sys.byteorder)
    ####

    if request.method == "GET":
        prm1 = request.args.get("param", "")
        prm2 = request.args.get("param2", "")
        step1_text = "param : " + prm1 + "\nparam2 : " + prm2 + "\n"
        if prm1 == "getget" and prm2 == "rerequest":
            return redirect(url_for("step2", prev_step_num = step1_num))
        return render_template("step1.html", text = step1_text)
    else: 
        return render_template("step1.html", text = "Not POST")


@app.route("/step2", methods=["GET", "POST"])
def step2():
    if request.method == "GET":

    #### 풀이와 관계없는 치팅 방지 코드
        if request.args.get("prev_step_num"):
            try:
                prev_step_num = request.args.get("prev_step_num")
                if prev_step_num == str(step1_num):
                    global step2_num
                    step2_num = int.from_bytes(os.urandom(16), sys.byteorder)
                    return render_template("step2.html", prev_step_num = step1_num, hidden_num = step2_num)
            except:
                return render_template("step2.html", text="Not yet")
        return render_template("step2.html", text="Not yet")
    ####

    else: 
        return render_template("step2.html", text="Not POST")

    
@app.route("/flag", methods=["GET", "POST"])
def flag():
    if request.method == "GET":
        return render_template("flag.html", flag_txt="Not yet")
    else:

        #### 풀이와 관계없는 치팅 방지 코드
        prev_step_num = request.form.get("check", "")
        try:
            if prev_step_num == str(step2_num):
        ####

                prm1 = request.form.get("param", "")
                prm2 = request.form.get("param2", "")
                if prm1 == "pooost" and prm2 == "requeeest":
                    return render_template("flag.html", flag_txt=FLAG)
                else:
                    return redirect(url_for("step2", prev_step_num = str(step1_num)))
            return render_template("flag.html", flag_txt="Not yet")
        except:
            return render_template("flag.html", flag_txt="Not yet")
            

app.run(host="0.0.0.0", port=8000)
```

<br>

## 웹 서비스 분석

소스 코드를 보면서 분석해도 쉽게 파악할 수 있지만, 문제의 설명에 나와있듯이 **STEP 1~2**를 거쳐 **FLAG 페이지**에 도달하면 플래그를 확인할 수 있는 문제이다.

그럼 `/step1`, `/step2`, `/flag` 엔드 포인트의 코드를 차례대로 분석해보며 플래그를 획득해보자.

<br>

### **/step1**

```py
@app.route("/step1", methods=["GET", "POST"])
def step1():

    #### 풀이와 관계없는 치팅 방지 코드
    global step1_num
    step1_num = int.from_bytes(os.urandom(16), sys.byteorder)
    ####

    if request.method == "GET":
        prm1 = request.args.get("param", "")
        prm2 = request.args.get("param2", "")
        step1_text = "param : " + prm1 + "\nparam2 : " + prm2 + "\n"
        if prm1 == "getget" and prm2 == "rerequest":
            return redirect(url_for("step2", prev_step_num = step1_num))
        return render_template("step1.html", text = step1_text)
    else: 
        return render_template("step1.html", text = "Not POST")
```

`/step1` 에서는 먼저, `step1_num` 변수에 랜덤값을 저장한다.

만약 해당 페이지에서 GET 요청이 발생한다면, `param`, `param2` 파라미터로 전달된 값을 `prm1`, `prm2` 변수에 저장한 후 `step1_text`를 화면에 출력해준다.

해당 페이지는 아래와 같고, 각 필드에 값을 입력하면 해당 값이 URL을 통해 `param1`, `param2` 파라미터에 저장되어, `/step1` 엔드 포인트로 GET 요청이 전송된다.

![image](assets/img/simple-web-request/image_1.png)

```py
if prm1 == "getget" and prm2 == "rerequest":
```

해당 코드를 살펴보면, 필드에 입력한 값이 각각 위와 같은 경우 `step2` 엔드 포인트로 `redirect()` 함수가 호출된다.

따라서, 해당 값을 각 필드에 입력해주면 STEP 2로 나아갈 수 있을 것이다.

**여기서 주목할 점이, 앞에서 랜덤값으로 설정한 `step1_num`을 파라미터인 `prev_step_num`에 대입하여 전달한다는 것이다.**

**결론적으로 `/step2?prev_step_num=step1_num`으로 GET 요청이 발생하게 된다.**

이 부분은 아래에서 계속 살펴보자.

<br>

### **/step2**

```py
@app.route("/step2", methods=["GET", "POST"])
def step2():
    if request.method == "GET":

    #### 풀이와 관계없는 치팅 방지 코드
        if request.args.get("prev_step_num"):
            try:
                prev_step_num = request.args.get("prev_step_num")
                if prev_step_num == str(step1_num):
                    global step2_num
                    step2_num = int.from_bytes(os.urandom(16), sys.byteorder)
                    return render_template("step2.html", prev_step_num = step1_num, hidden_num = step2_num)
            except:
                return render_template("step2.html", text="Not yet")
        return render_template("step2.html", text="Not yet")
    ####

    else: 
        return render_template("step2.html", text="Not POST")
```

앞에서 설명했듯이 `/step1`에서 조건에 따라 필드에 값을 입력해주면 아래와 같이 `/step2`에 도달할 수 있게 된다.

![image](assets/img/simple-web-request/image_2.png)

참고로 코드를 잘 살펴보면, `prev_step_num` 파라미터에 값이 존재하더라도 `/step1` 에서 설정해준 `step1_num` 값과 동일하지 않다면 "Not yet"이 출력된다.

따라서 `/step1`을 통해서만 `/step2`에 도달할 수 있다는 의도를 확인할 수 있다.

정상적인 과정을 통해 들어왔다면, `step2_num`에 랜덤값을 대입해주고, `prev_step_num`과 `hidden_num` 값을 세팅해준 후 **step2.html** 파일을 렌더링해준다.

<br>

### **step2.html**

```html
{% extends "base.html" %}
{% block title %}Step2 {% endblock %}

{% block head %}
  {{ super() }}
  <style type="text/css">
    .important { color: #336699; }
  </style>
{% endblock %}

{% block content %}
{% if prev_step_num and hidden_num %}
  <form action="/flag" method="post">
    <p>param <input type="text" name="param"/></p>
    <p>param2 <input type="text" name="param2"/></p>
    <input type="hidden" name="check" value="{{ hidden_num }}">
    <input type="submit"/><br/>
  </form>
{% else %}
  <pre>{{ text }}</pre>
{% endif %}
{% endblock %}
```

`/step2`에서 렌더링된 `step2.html` 파일은 위와 같다.

앞에서 살펴봤듯이 해당 html 파일이 렌더링하는 페이지에는 `param`과 `param2` 필드에 값을 입력하여 전송할 수 있었는데,

해당 값은 `<form>` 태그를 통해 `/flag` 페이지에 **POST** Request의 데이터로 전달된다.

그리고 `<input type = "hidden">` 필드에서는, 페이지를 렌더링할 때 전달해줬던 `hidden_num` 값이 저장되어 POST 요청의 데이터로 함께 전달된다.

그럼 `/flag` 페이지를 살펴보자.

<br>

### **/flag**

```py
@app.route("/flag", methods=["GET", "POST"])
def flag():
    if request.method == "GET":
        return render_template("flag.html", flag_txt="Not yet")
    else:

        #### 풀이와 관계없는 치팅 방지 코드
        prev_step_num = request.form.get("check", "")
        try:
            if prev_step_num == str(step2_num):
        ####

                prm1 = request.form.get("param", "")
                prm2 = request.form.get("param2", "")
                if prm1 == "pooost" and prm2 == "requeeest":
                    return render_template("flag.html", flag_txt=FLAG)
                else:
                    return redirect(url_for("step2", prev_step_num = str(step1_num)))
            return render_template("flag.html", flag_txt="Not yet")
        except:
            return render_template("flag.html", flag_txt="Not yet")
```

여기서도 `/step2`와 동일하게, 앞에서 `hidden_num`을 저장해줬던 데이터(`name = "check"`)를 가져와서 `step2_num`과 비교해주는 루틴을 가진다.

이를 통해 `/step2`에서 `/flag` 페이지로 이동한게 맞는지 검증하는 과정을 거치고, 맞다면 `/step2`에서 form을 통해 입력한 값들을 `prm1`, `prm2`에 받아온다.

```py
if prm1 == "pooost" and prm2 == "requeeest":
```

이 부분을 통해 `/step2`에서 각 필드에 위 값을 입력해주면 플래그를 출력하는 `flag.html` 파일을 렌더링하는 것을 확인할 수 있다.

![image](assets/img/simple-web-request/image_3.png)

![image](assets/img/simple-web-request/image_4.png)

이 문제는 문제 푸는 것 자체는 매우 쉬운 편에 속하지만, flask가 익숙하지 않아서 그냥 공부하는 겸 쓸데없이 자세히 분석해봤다.

{% endraw %}