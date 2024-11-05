---
title: Flying Chars
description: Dreamhack [Wargame] - Flying Chars 
author: juhyeongkim
date: 2024-11-05 09:38:00 +0900
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

[문제 링크](https://dreamhack.io/wargame/challenges/850)

{% raw %}

## 문제 설명

날아다니는 글자들을 멈춰서 전체 문자열을 알아내세요! 플래그 형식은 **DH{전체 문자열}** 입니다.

❗첨부파일을 제공하지 않는 문제입니다.

❗플래그에 포함된 알파벳 중 x, s, o는 모두 소문자입니다.

❗플래그에 포함된 알파벳 중 C는 모두 대문자입니다.

<br>

## Source code

```html
<html>

<head>
    <title>Web</title>
</head>

<body>
    <div id="box">
        <img src="/static/images/10.png"
            style="display: block; width: 10px; height: 10px; transform: translateX(388.57px);"><img
            src="/static/images/17.png"
            style="display: block; width: 10px; height: 10px; transform: translateX(427.733px);"><img
            src="/static/images/13.png"
            style="display: block; width: 10px; height: 10px; transform: translateX(450.081px);"><img
            src="/static/images/7.png"
            style="display: block; width: 10px; height: 10px; transform: translateX(963.55px);"><img
            src="/static/images/16.png"
            style="display: block; width: 10px; height: 10px; transform: translateX(1341.15px);"><img
            src="/static/images/8.png"
            style="display: block; width: 10px; height: 10px; transform: translateX(325.877px);"><img
            src="/static/images/14.png"
            style="display: block; width: 10px; height: 10px; transform: translateX(1629.43px);"><img
            src="/static/images/2.png"
            style="display: block; width: 10px; height: 10px; transform: translateX(968.19px);"><img
            src="/static/images/9.png"
            style="display: block; width: 10px; height: 10px; transform: translateX(1660.2px);"><img
            src="/static/images/5.png"
            style="display: block; width: 10px; height: 10px; transform: translateX(328.543px);"><img
            src="/static/images/11.png"
            style="display: block; width: 10px; height: 10px; transform: translateX(965.736px);"><img
            src="/static/images/6.png"
            style="display: block; width: 10px; height: 10px; transform: translateX(420.045px);"><img
            src="/static/images/12.png"
            style="display: block; width: 10px; height: 10px; transform: translateX(1704.07px);"><img
            src="/static/images/3.png"
            style="display: block; width: 10px; height: 10px; transform: translateX(1489.69px);"><img
            src="/static/images/0.png"
            style="display: block; width: 10px; height: 10px; transform: translateX(766.076px);"><img
            src="/static/images/19.png"
            style="display: block; width: 10px; height: 10px; transform: translateX(1171.88px);"><img
            src="/static/images/4.png"
            style="display: block; width: 10px; height: 10px; transform: translateX(955.724px);"><img
            src="/static/images/15.png"
            style="display: block; width: 10px; height: 10px; transform: translateX(804.542px);"><img
            src="/static/images/18.png"
            style="display: block; width: 10px; height: 10px; transform: translateX(230.898px);"><img
            src="/static/images/1.png"
            style="display: block; width: 10px; height: 10px; transform: translateX(373.315px);">
    </div>

    <style type="text/css">
        body {
            display: flex;
            width: 100vw;
            height: 100vh;
            padding: 0px;

        }

        #box {
            display: flex;
            flex-direction: column;
            justify-content: space-around;
            width: 90%;
            height: 100%;
        }
    </style>

    <script type="text/javascript">
        const img_files = ["/static/images/10.png", "/static/images/17.png", "/static/images/13.png", "/static/images/7.png", "/static/images/16.png", "/static/images/8.png", "/static/images/14.png", "/static/images/2.png", "/static/images/9.png", "/static/images/5.png", "/static/images/11.png", "/static/images/6.png", "/static/images/12.png", "/static/images/3.png", "/static/images/0.png", "/static/images/19.png", "/static/images/4.png", "/static/images/15.png", "/static/images/18.png", "/static/images/1.png"];
        var imgs = [];
        for (var i = 0; i < img_files.length; i++) {
            imgs[i] = document.createElement('img');
            imgs[i].src = img_files[i];
            imgs[i].style.display = 'block';
            imgs[i].style.width = '10px';
            imgs[i].style.height = '10px';
            document.getElementById('box').appendChild(imgs[i]);
        }

        const max_pos = self.innerWidth;
        function anim(elem, pos, dis) {
            function move() {
                pos += dis;
                if (pos > max_pos) {
                    pos = 0;
                }
                elem.style.transform = `translateX(${pos}px)`;
                requestAnimationFrame(move);
            }
            move();
        }

        for (var i = 0; i < 20; i++) {
            anim(imgs[i], 0, Math.random() * 60 + 20);
        }
    </script>

</body>

</html>
```

<br>

## 분석

이번 문제의 소스코드는 위와 같고, 페이지에 들어가보면 아래와 같이 문자들이 계속 위치를 바꾸며 날아다니는 것을 확인할 수 있다.

![alt text](assets/img/Flying_Chars/image_1.png) 

문자들의 위치를 바꾸는 코드를 수정하여, 문자들의 위치가 바뀌지 않고 고정되도록 해주면 될 것 같다는 계획을 가지고 코드를 분석해보자.

먼저 자바스크립트 코드를 하나씩 살펴보자.

<br>

### 1.

```javascript
<script type="text/javascript">
    const img_files = ["/static/images/10.png", "/static/images/17.png", "/static/images/13.png", "/static/images/7.png", "/static/images/16.png", "/static/images/8.png", "/static/images/14.png", "/static/images/2.png", "/static/images/9.png", "/static/images/5.png", "/static/images/11.png", "/static/images/6.png", "/static/images/12.png", "/static/images/3.png", "/static/images/0.png", "/static/images/19.png", "/static/images/4.png", "/static/images/15.png", "/static/images/18.png", "/static/images/1.png"];
    var imgs = [];
    for (var i = 0; i < img_files.length; i++) {
        imgs[i] = document.createElement('img');
        imgs[i].src = img_files[i];
        imgs[i].style.display = 'block';
        imgs[i].style.width = '10px';
        imgs[i].style.height = '10px';
        document.getElementById('box').appendChild(imgs[i]);
    }
```
해당 코드를 보면 `img_files` 배열에 여러 이미지들을 저장해주는데, 당연히 예상할 수 있듯이 각 이미지가 flag의 한 글자를 나타낸다고 예상할 수 있다.

그리고 `imgs` 배열을 추가로 선언하여 `<img>` 태그를 가지는 **Element**를 생성해주고, 해당 element의 `src`, `style`을 지정해준 후 `id = 'box'` element 내에 Child로 등록해준다.

근데 여기서 옥의 티가 있는게, 크롬 개발자 도구에서 `id = 'box'`인 element 내의 `<img>` 태그를 살펴보면 각 문자 이미지들이 랜더링 되고 있는데,

해당 태그의 `src` 속성 값에 마우스 포인터를 올리면 화면에서 날아다니고 있는 원본 이미지가 바로 보인다.

그래서 바로 flag를 하나씩 구하는 방법도 있겠지만, 문제에서 의도한 방법은 아닐테니 이렇게 확인할 수도 있다는 것만 알고 넘어가자.

![alt text](assets/img/Flying_Chars/image_2.png)

<br>

### 2. 

```javascript
const max_pos = self.innerWidth;
    function anim(elem, pos, dis) {
        function move() {
            pos += dis;
            if (pos > max_pos) {
                pos = 0;
            }
            elem.style.transform = `translateX(${pos}px)`;
            requestAnimationFrame(move);
        }
        move();
    }

    for (var i = 0; i < 20; i++) {
        anim(imgs[i], 0, Math.random() * 60 + 20);
    }
```

위 코드를 살펴보면, `anim(elem, pos, dis)` 함수와 `move()` 함수가 존재하는 것을 확인할 수 있다.

이름부터 flag 문자 이미지를 날아다니게 하는 함수들인 것 같은데, 한번 살펴보자.

먼저 `max_pos` 에는 `self.innerWidth`를 대입하여`window` 객체인 현재 브라우저의 너비값을 저장해준다.

그리고 `anim(elem, pos, dis)` 함수 내에서는 `move()` 함수를 정의해준 후, 마지막에 `move(` 함수를 호출하고 종료한다.

`move()` 함수 내에서는 `anim(elem, pos, dis)` 함수에서 받은 argument를 통해 `elem`의 `pos`에 `dis`를 더해주며 X축 방향으로 이동 `pos` 만큼 이동시켜준다.

여기서 `max_pos`를 넘어서면, 다시 브라우저 왼쪽 끝으로 돌아오도록 `pos = 0`으로 설정해준다.

그리고 `requestAnimationFrame(move);` 함수를 호출해주는데, 이 함수는 브라우저의 화면 갱신 주기(일반적으로 60fps)에 맞춰 `move()` 함수를 재귀적으로 호출해주는 함수이다.

`anim(elem, pos, dis)` 함수 내에 `move()` 함수를 중첩하여 선언해준 이유도, `elem, ps, dis` argument 값을 유지하면서 계속 `move()` 함수를 호출하기 위함이다.

이렇게 되면 각 flag 이미지 문자가 한번만 이동하는 것이 아닌 60fps 마다 계속 `pos`를 이동하게 되어 글자가 빠르게 날아다니는 것처럼 보이게 된다.

`anim(elem, pos, dis)` 함수 호출은 아래의 코드를 통해 `imgs` 배열의 각 원소마다 랜덤한 `dis`에 따라 움직이도록 호출해준다.

```javascript
for (var i = 0; i < 20; i++) {
    anim(imgs[i], 0, Math.random() * 60 + 20);
}
```

<br>

## 플래그 찾기

브라우저가 웹사이트를 랜더링할 때, 

```javascript
for (var i = 0; i < 20; i++) {
    anim(imgs[i], 0, Math.random() * 60 + 20);
}
```

코드가 실행되어, 계속 재귀적으로 `move()` 함수를 호출하여 flag 문자가 날아다니게 된다고 하였다.

그럼, 여기서 아래와 같이 argument인 `dis` 값을 0으로 세팅해준 후 반복문을 통해 `anim(imgs[i], 0, 0);`을 호출해주면 모든 flag 문자들이 왼쪽 끝에 붙을 것이다.

개발자 모드의 `Console` 탭에서 아래의 코드를 입력해주면 모든 flag 문자가 왼쪽 끝에 붙어서 날아다니지 않는 것을 확인할 수 있다.

```javascript
for (var i = 0; i < 20; i++) {
    anim(imgs[i], 0, 0);
}
```

![image_3](assets/img/Flying_Chars/image_3.png)

<br>

### 참고(내용 추가 필요)

`Console` 탭에서 `dis = 0`으로 세팅 후 `move()`를 호출해주어도, 처음에 웹사이트를 랜더링할 때 수행된 아래의 코드에서 세팅된 `dis` 값으로 계속 `move()` 함수가 호출되고 있을 것이라고 생각이 들었다.

```javascript
for (var i = 0; i < 20; i++) {
    anim(imgs[i], 0, Math.random() * 60 + 20);
}
```

그럼 `dis` 값이 2개인데, `requestAnimationFrame(move)`는 어떤 `dis` 값을 가지는 `move()` 함수를 호출하는지 궁금했다.

완전히 자세히 찾아보지는 않아서 정확하지는 않지만, **자바스크립트의 비동기 처리 방식 때문에 마지막에 호출된** `dis = 0` 값을 가지는 `move()` 함수에 의해 화면이 랜더링 되기 때문에 이미지가 이동하지 않는다고 한다.

`requestAnimationFrame(move)` 함수에 의해 `move()` 함수가 다른 `dis` 값으로 총 2번 실행되는 것은 맞지만,

비동기적으로 브라우저 렌더링 주기에 맞춰 화면이 렌더링되기 때문에, 마지막에 실행된 `dis = 0` 인 `move()` 함수가 앞의 `move()` 함수의 이동을 덮어쓰게 된다고 이해하면 될 것 같다.

**결론적으로** `requestAnimationFrame(move)` 함수는 브라우저 렌더링 주기가 오기 전에 비동기적으로 총 2번 실행되어 `<img>` element의 `transform` 속성 값을 각각 변경하지만,

브라우저 렌더링 주기가 왔을 때 렌더링하는 `<img>` element의 `transform` 속성 값은 마지막에 호출된 `dis = 0` 값을 가지는 `move()` 함수에 의해 렌더링되기 때문에 이미지가 이동하지 않는 것이다.

**첫 번째 `requestAnimationFrame(move)` 실행 -> 두 번째 `requestAnimationFrame(move)` 실행 -> 브라우저 렌더링 -> 반복...**

더 자세한 내용은 자바스크립트에 대해서 더 공부해본 후 이 내용을 다시 찾아봐야겠다.

{% endraw %}