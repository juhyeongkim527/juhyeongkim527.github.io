---
title: '[Dreamhack] file-download-1'
description: Dreamhack [Wargame] - file-download-1
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

[문제 링크](https://dreamhack.io/wargame/challenges/37)

{% raw %}

## 서론 

`file-download-1` 워게임의 목표는 **File Download Vulnerability** 취약점을 이용해 플래그를 획득하는 것이다. 문제의 설명은 아래와 같다.

---

File Download 취약점이 존재하는 웹 서비스입니다.

`flag.py`를 다운로드 받으면 플래그를 획득할 수 있습니다.

---

```py
#!/usr/bin/env python3
import os
import shutil

from flask import Flask, request, render_template, redirect

from flag import FLAG

APP = Flask(__name__)

UPLOAD_DIR = 'uploads'


@APP.route('/')
def index():
    files = os.listdir(UPLOAD_DIR)
    return render_template('index.html', files=files)


@APP.route('/upload', methods=['GET', 'POST'])
def upload_memo():
    if request.method == 'POST':
        filename = request.form.get('filename')
        content = request.form.get('content').encode('utf-8')

        if filename.find('..') != -1:
            return render_template('upload_result.html', data='bad characters,,')

        with open(f'{UPLOAD_DIR}/{filename}', 'wb') as f:
            f.write(content)

        return redirect('/')

    return render_template('upload.html')


@APP.route('/read')
def read_memo():
    error = False
    data = b''

    filename = request.args.get('name', '')

    try:
        with open(f'{UPLOAD_DIR}/{filename}', 'rb') as f:
            data = f.read()
    except (IsADirectoryError, FileNotFoundError):
        error = True


    return render_template('read.html',
                           filename=filename,
                           content=data.decode('utf-8'),
                           error=error)


if __name__ == '__main__':
    if os.path.exists(UPLOAD_DIR):
        shutil.rmtree(UPLOAD_DIR)

    os.mkdir(UPLOAD_DIR)

    APP.run(host='0.0.0.0', port=8000)
```

`app.py`의 전체 코드는 위와 같고, 코드 내에 존재하는 웹 서비스의 엔드포인트를 하나씩 살펴보자.

<br>

## 웹 서비스 분석

### 엔드포인트 : **/**

```py
UPLOAD_DIR = 'uploads'

@APP.route('/')
def index():
    files = os.listdir(UPLOAD_DIR)
    return render_template('index.html', files=files)

```

먼저 인덱스 페이지에서는, `listdir()` 함수를 통해, `UPLOAD_DIR(uploads)` 디렉토리에 있는 모든 파일과 디렉토리의 이름을 배열 형태로 리턴하여 `files`에 저장한다.

그리고 `index.html` 파일에 인자로 `files`를 전달하는 것을 보아, 인덱스 페이지에서는 이미 존재하거나 새로 업로드된 파일의 목록을 출력해주는 것으로 보인다.

`index.html`을 보면, 아래와 같은 파일이 존재한다.

```html
{% for file in files  %}
  <li><a href="/read?name={{ file }}">{{ file }}</a></li>
{% endfor %}
```

인자로 전달 받은 `files` 배열에 대해 반복문을 순회하며, 해당 원소(파일 또는 디렉토리)의 이름과 `/read` 엔드포인트로 이동하는 하이퍼링크를 제공한다.

업로드 페이지인 `/upload` 엔드포인트에서 `asd`라는 파일을 업로드한 후, 인덱스 페이지로 돌아오면 아래와 같이 하이퍼링크가 뜨고, 클릭하면 `/read` 엔드포인트로 이동한다.

<img width="977" alt="image" src="https://github.com/user-attachments/assets/6cb412d2-7e15-4b5f-a052-e7dc87ca5b4b">

<img width="502" alt="image" src="https://github.com/user-attachments/assets/b3c09cb6-6a43-48dd-b061-480c5f79ac75">

<img width="1023" alt="image" src="https://github.com/user-attachments/assets/f0afff37-b31e-4e2b-90c3-7d63ae392b7b">

그럼 바로, `/upload` 엔드포인ㄴ트와 `/read` 엔드포인트에 대해서 분석해보자.

<br>

### 엔드포인트 : **/upload**

```py
@APP.route('/upload', methods=['GET', 'POST'])
def upload_memo():
    if request.method == 'POST':
        filename = request.form.get('filename')
        content = request.form.get('content').encode('utf-8')

        if filename.find('..') != -1:
            return render_template('upload_result.html', data='bad characters,,')

        with open(f'{UPLOAD_DIR}/{filename}', 'wb') as f:
            f.write(content)

        return redirect('/')

    return render_template('upload.html')
```

<img width="998" alt="image" src="https://github.com/user-attachments/assets/5ed90f30-619a-4b93-be65-e7a1f2cfdbc3">

`/upload` 엔드포인트 코드를 잘 보면, `GET` 요청이 온 경우는 `upload.html` 파일을 렌더링해주고,

`POST` 요청이 온 경우 `filename`과 `content`를 `form`을 통해 전달받는다.

그런데 여기서, `filename`에 `..`이 존재한다면, 파일을 업로드하지 않고, `"bad characters,,"` 문자열을 전달하고 끝낸다.

이를 통해 `..`와 같이 상위 디렉토리로 이동하는 상대 경로 문자열을 필터링하는 것을 알 수 있고, **Path Traversal** 취약점 공격은 어려운 것을 알 수 있다.

만약 필터링에 걸리지 않는다면, `wb`인 **바이너리 쓰기** 모드로 `{UPLOAD_DIR}/{filename}` 파일을 열어서 `content`의 내용을 파일에 써준다.

참고로, `wb`는 파일이 존재한다면 덮어쓰고, 존재하지 않으면 생성하여 쓰는 모드이며, `with open() as f`는 파일을 열고, `f`를 통해 파일에 접근한 후 자동으로 `close`를 해주는 구문이다.

끝난 후에는 `return redirect('/')`로 인덱스 페이지로 이동해준다.

<br>

### 엔드포인트 : **/read**

```py
@APP.route('/read')
def read_memo():
    error = False
    data = b''

    filename = request.args.get('name', '')

    try:
        with open(f'{UPLOAD_DIR}/{filename}', 'rb') as f:
            data = f.read()
    except (IsADirectoryError, FileNotFoundError):
        error = True


    return render_template('read.html',
                           filename=filename,
                           content=data.decode('utf-8'),
                           error=error)
```

해당 엔드포인트는 인덱스 페이지에서는 보이지 않는 엔드포인트로, URL을 통해서 접근가능하다.

`GET` 요청이 왔을 때, `name` 파라미터에 저장된 값을 가져와서 `filename`에 저장한 후, `/upload` 엔드포인트에서와 비슷한 방법으로 파일을 열고 `data` 변수에 파일의 모든 내용을 읽어서 저장한다.

만약 `open` 과정에서 파일이 존재하지 않는다면, `error`를 설정해준다.

그리고 `read.html` 페이지를 랜더링하며, `filename`, `content`, `error`를 인자로 전달해준다.

```html
{% if error %}
<h1>{{ filename }} does not exist. :(</h1>
{% else %}
<h1>{{ filename }} Memo</h1><br/>
  <div class="row">
    <div class="col-md-12 form-group">
      <label for="FileData">Content</label>
      <textarea id="FileData" class="form-control" rows="5" name="content" readonly>{{ content }}</textarea>
    </div>
  </div>
```

위 코드는 `read.html` 파일이다.

만약 `error`가 존재한다면 에러메시지를 출력해주고, 존재하지 않는다면 `content` 내용을 출력해준다.

해당 엔드포인트의 취약점을 생각해보면, `/upload` 엔드포인트와 달리 `name` 파라미터에 `..`와 같은 상대 경로 이동 문자열이 존재하는지 검사하지 않는다.

따라서, 실제 어떤 파일의 내용을 읽을지 정해주는 `filename`에 저장될 `name` 파라미터에 `..`와 같은 상대 경로 이동 문자열을 통해 **Path Traversal** 취약점 공격이 가능하다.

<br>

## Exploit

그럼 `/read` 엔드포인트의 **Path Traversal** 취약점을 통해, `flag.py`의 내용을 읽어보자.

플래그가 저장된 파일의 이름은 알고 있지만, 해당 파일이 어느 디렉토리에 존재하는지는 알려져있지 않다.

따라서, 상대경로를 탐색하며 하나씩 차례대로 확인해봤을 때, `/read?name=../flag.py`을 통해, `../flag.py`에서 해당 파일을 찾을 수 있었다.

### 1. **/read?name=flag.py**

<img width="482" alt="image" src="https://github.com/user-attachments/assets/c47a0f9f-974a-44b6-ade1-c63cfb5ef18f">

### 2. **/read?name=../flag.py**

<img width="998" alt="image" src="https://github.com/user-attachments/assets/79b3ee71-2bbf-4a06-accc-fa20b817491c">

<br>

#### 참고

이번 문제에서 업로드하는 파일에 대한 검증이 존재하지 않아서, 웹 셸 업로드 공격이 가능한게 아닌가라는 생각으로 웹 셸을 업로드해보니 코드 실행이 불가능했다.

<img width="1023" alt="image" src="https://github.com/user-attachments/assets/0cf4791d-50bb-4cf4-a2e4-a3f3c21ad31e">

`image-storage` 워게임에서는 `<li><a href='{$directory}{$value}'>".$value."</a></li><br/>`를 통해, 업로드한 웹 셸에 직접 접근하지만,

이번 문제에서는 `f.read()`를 통해서 업로드한 웹 셸에 직접 접근하는게 아니라, 파일에 적힌 데이터만 읽어서 출력하기 때문인 것 같다.

그리고 참고로, `php`와 달리 파이썬에서는 웹 셸에 접근하는 것만으로는 실행을 할 수 없다는 것도 봤는데, 이 부분은 더 공부해본 후 보완해봐야겠다.

<br>

## 마치며

**Path Traversal** 취약점을 이용한, **File Download Vulnerability** 공격을 통해 문제를 해결하였다.

이러한 공격으로부터 서비스를 보호하려면, `/upload` 엔드포인트에서처럼 `..`와 같은 디렉토리를 이동하는 문자열을 필터링하여 Path Traversal 취약점을 막아야 한다.

이번 문제에서 처럼, 이때 특정 페이지(`/read`) 또는 특정 기능에 대해 충분히 검사하지 않거나, 페이지 간 검사 수준이 다르면 공격자는 해당 취약점을 악용하여 파일 다운로드 공격을 시도할 수 있다.

따라서 모든 페이지에서 일관되게 상위 디렉토리로 이동 시도를 차단해야한다. 

`".."` 외에도 파일 시스템에 대해 부적절한 접근을 시도할 수 있는 문자열은 아래와 같다.

| 문자열 | 역할 및 설명 |
|--------|-------------|
| `/`    | 파일 경로에서 디렉터리 구분자로 사용됩니다. |
| `\`    | Windows 운영 체제에서 파일 경로에서 디렉터리 구분자로 사용됩니다. |
| `:`    | Windows 운영 체제에서 드라이브와 파일 경로를 구분하는데 사용됩니다. |
| `~`    | 홈 디렉터리를 나타내는데 사용됩니다. |


또 다른 파일 다운로드 공격으로부터 서비스를 보호하는 방법은, 특정 파일 유형(이미지, 문서, 텍스트 등)만 허용하도록 확장자를 검증하는 것이다. (웹 셀 공격을 막기 위해)

확장자에 대한 **화이트리스트(허용할 항목들의 배열)** 를 만들어 검사하고, 화이트리스트에 없는 확장자를 가진 파일(**블랙리스트로 정하기도 함**)을 차단하면 파일 다운로드 공격을 예방할 수 있다.

{% endraw %}