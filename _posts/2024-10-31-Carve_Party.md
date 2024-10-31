---
title: Carve Party
description: Dremhack [Wargame] - Carve Party
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

[문제 링크](https://dreamhack.io/wargame/challenges/96)

## 문제 설명

해당 문제는 하나의 `jack-o-lantern.html` 파일로 이루어져있으며, 해당 HTML 파일을 로컬호스트로 랜더링하면 아래의 화면이 나온다.

<img width="706" alt="image" src="https://github.com/user-attachments/assets/0f0313e4-fc55-48dd-8e2f-313f564eaca4">

화면에 적혀있는대로 호박을 클릭해보면, 아래에 적혀있는 클릭의 수가 1만큼 줄어드는 것을 확인할 수 있다.

뭔가 예상을 해봤을 때 총 클릭을 10000번하면 플래그가 나올 것 같지만, 이건 너무 무식한 방법이므로 `html` 파일을 한번 살펴보자.

<br>

## 소스코드 분석

파일에서 `HTML`과 `CSS` 부분은 크게 중요하지 않아 보이기 때문에, `<script>` 태그가 존재하는 자바스크립트 코드 부분을 살펴보면 아래와 같다.

```javascript
<script>
    var pumpkin = [124, 112, 59, 73, 167, 100, 105, 75, 59, 23, 16, 181, 165, 104, 43, 49, 118, 71, 112, 169, 43, 53];
    var counter = 0;
    var pie = 1;

    function make() {
      if (0 < counter && counter <= 1000) {
        $('#jack-nose').css('opacity', (counter) + '%');
      }
      else if (1000 < counter && counter <= 3000) {
        $('#jack-left').css('opacity', (counter - 1000) / 2 + '%');
      }
      else if (3000 < counter && counter <= 5000) {
        $('#jack-right').css('opacity', (counter - 3000) / 2 + '%');
      }
      else if (5000 < counter && counter <= 10000) {
        $('#jack-mouth').css('opacity', (counter - 5000) / 5 + '%');
      }

      if (10000 < counter) {
        $('#jack-target').addClass('tada');
        var ctx = document.querySelector("canvas").getContext("2d"),
          dashLen = 220, dashOffset = dashLen, speed = 20,
          txt = pumpkin.map(x => String.fromCharCode(x)).join(''), x = 30, i = 0;

        ctx.font = "50px Comic Sans MS, cursive, TSCu_Comic, sans-serif";
        ctx.lineWidth = 5; ctx.lineJoin = "round"; ctx.globalAlpha = 2 / 3;
        ctx.strokeStyle = ctx.fillStyle = "#1f2f90";

        (function loop() {
          ctx.clearRect(x, 0, 60, 150);
          ctx.setLineDash([dashLen - dashOffset, dashOffset - speed]); // create a long dash mask
          dashOffset -= speed;                                         // reduce dash length
          ctx.strokeText(txt[i], x, 90);                               // stroke letter

          if (dashOffset > 0) requestAnimationFrame(loop);             // animate
          else {
            ctx.fillText(txt[i], x, 90);                               // fill final letter
            dashOffset = dashLen;                                      // prep next char
            x += ctx.measureText(txt[i++]).width + ctx.lineWidth * Math.random();
            ctx.setTransform(1, 0, 0, 1, 0, 3 * Math.random());        // random y-delta
            ctx.rotate(Math.random() * 0.005);                         // random rotation
            if (i < txt.length) requestAnimationFrame(loop);
          }
        })();
      }
      else {
        $('#clicks').text(10000 - counter);
      }
    }

    $(function () {
      $('#jack-target').click(function () {
        counter += 1;
        if (counter <= 10000 && counter % 100 == 0) {
          for (var i = 0; i < pumpkin.length; i++) {
            pumpkin[i] ^= pie;
            pie = ((pie ^ 0xff) + (i * 10)) & 0xff;
          }
        }
        make();
      });
    });
  </script>
```

제일 먼저 보이는 부분이 `make()` 함수에서 `count` 값을 비교해서 `css`를 변경해주는 부분인데, 개발자 도구를 통해 `count` 변수에 값을 대입해서 변경해보며 화면을 확인해보면 아래와 같이 `css`가 변하는 것을 확인할 수 있었다.

<img width="1040" alt="image" src="https://github.com/user-attachments/assets/bc0c37a4-9885-4468-9f2d-d03a523f92db">

그래서 처음에는 `counter`를 한번에 `10000` 이상으로 세팅해주면 플래그가 나오지 않을까라고 소스코드 분석 없이 간단히 생각한 후 입력해봤는데, 아래와 같이 이상한 값이 출력되었다.

<img width="1016" alt="image" src="https://github.com/user-attachments/assets/890db9da-4e35-4c1d-94a1-18c04f54bae8">

뭔가 한번에 `counter`를 설정하는 것은 아닌 것 같아서, 소스코드를 다시 살펴보니 `counter > 10000`인 경우, 플래그를 보여주기 위해 `ctx`, `txt`, `x` 값을 업데이트하는 로직이 존재하므로 `counter > 10000`을 만족해야 하는 것은 맞다고 생각을 했다.

그리고 더 아래를 살펴보면 해당 문제에서 중요한 `click` 이벤트 핸들러 코드가 보인다.

```javascript
$(function () {
      $('#jack-target').click(function () {
        counter += 1;
        if (counter <= 10000 && counter % 100 == 0) {
          for (var i = 0; i < pumpkin.length; i++) {
            pumpkin[i] ^= pie;
            pie = ((pie ^ 0xff) + (i * 10)) & 0xff;
          }
        }
        make();
      });
    });
```

이 함수를 보면, 호박을 클릭하는 `$('#jack-target').click()` 이벤트가 발생할 때, 핸들러 코드를 통해 `counter` 값을 1 증가시키고 `counter`가 `10000`보다 작고 `100` 으로 나누어지는 경우,

`pumkin` 배열과, `pie` 변수를 XOR 연산으로 계속 업데이트 해준다.

`pumkin` 배열과 `pie` 변수의 값은 위의 `make()` 함수에서 `counter > 10000`이 만족되는 경우 참조되어 계산되는데, 해당 배열의 원소와 변수가 핸들러 코드의 루틴대로 정상적으로 세팅되야 플래그가 출력되는 것이구나라고 예측할 수 있었다.

따라서 `$('#jack-target').click()` 이벤트를 반복문을 통해 `10000`번 수행하여, 핸들러 코드의 모든 루틴이 수행되도록 하여 결과를 확인해보니 아래와 같이 정상적으로 플래그가 출력되었다.

<img width="1109" alt="image" src="https://github.com/user-attachments/assets/8503d2b7-6f4c-430d-95e4-18493ee82485">

참고로, `jQuery`를 처음 보지만 `$(function () {});`는 document가 준비되면 실행하게 되는 함수가 정의된 부분이고,

`$('#jack-target').click(function () {});` `#jack-target` 요소에 `click` 이벤트가 발생했을 때의 핸들러 코드를 등록하는 부분이라고 한다.

그래서 시험삼아 아래의 코드를 `10000`번 수행하도록 `console`에 반복문을 통해 입력해주었는데, 이후 호박을 한번 클릭해주면 `counter` 값이 `10000`을 넘어가면서 위와 똑같이 정상적인 플래그가 출력되었다.

<img width="1231" alt="image" src="https://github.com/user-attachments/assets/e9800e73-d8a9-4a0e-9360-0a111ab5a045">

처음엔 왜 그런지 이해못하였는데, 잘 생각해보니 `console`에 해당 반복문을 입력해주면 document가 준비되었을 때, 해당 반복문 내의 `function`이 `10000`번 수행되게 된다.

그럼 `$('#jack-target').click()`의 핸들러가 `10000`번 모두 중복되어 등록되게 되어, 한번만 클릭을 해줘도 핸들러 코드가 `10000`번 수행되어 플래그를 출력하기 위한 핸들러 코드의 루틴이 한번만에 전부 수행되게 된다.

따라서 `console`에 입력해준 것만으로는 `counter`를 증가시키지 않지만, `click` 이벤트 핸들러 코드를 `10000`번 등록해주게 되어, 이후에 한번만 클릭해줘도 핸들러 코드가 `10000`번 수행되어 기존 루틴대로 순차적으로 수행 후 `make()`에서 정상적인 플래그가 출력되는 것이다.

이 문제의 소스코드는 `jQuery`가 많이 사용되었기 때문에, 처음 볼 때 소스코드를 보는게 많이 익숙하지 않았다. 다음에 `jQuery`를 한번 공부하고 다시 해당 문제를 보면 더 이해가 잘 될 것 같다.
