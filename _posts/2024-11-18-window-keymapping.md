---
title: '[UTM] Windows 11 키보드 매핑'
description: '[UTM] Winodws 11에서 맥 키보드와 똑같이 매핑하는 방법'
author: juhyeongkim
date: 2024-11-18 05:00:00 +0900
categories: [UTM]
tags: [UTM, Windows]
# toc: false
# comments: false
# math: true
# mermaid: true
# image:
# path: 
    # lqip: 
    # alt: 
---

UTM에서 가상머신으로 Windows 11을 사용하고 있는데, 맥북을 사용 중이기 때문에 키매핑 때매 사용하는데 너무 불편했다.

그래서 맥 키보드와 동일하게 동작하도록(한/영, command키) 매핑하는 방법을 찾아보니 아래와 같았다.

<br>

## 1. 레지스트리 편집기 열기

![alt text](assets/img/key_mapping/image_0.png)

윈도우에서 **레지스트리 편집기** 라는 응용 프로그램을 열어준다.

<br>

## 2. 경로 찾기

![alt text](assets/img/key_mapping/image_1.png)

그리고 위 화면과 같이 `컴퓨터\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layout` 경로로 이동해준다.

Keyboard Layouts가 아닌 **Keyboard Layout**에 들어가야 하는거 주의하자.

위 스크린샷에는 이미 **Scancode Map**을 생성했기 때문에, 존재하지만 원래는 해당 파일없이 **(기본값)** 파일만 존재하므로 생성해줘야 한다.

<br>

## 3. Scancode Map 생성

![alt text](assets/img/key_mapping/image_2.png)

위와 같이 **이진값(B)** 로 파일을 생성하여 **Scancode Map**이라는 이름으로 변경해준 후, 더블 클릭하여 파일 내용을 아래와 같이 수정해준다.

![alt text](assets/img/key_mapping/image_3.png)

```
00 00 00 00 00 00 00 00
04 00 00 00 1D 00 5B E0
72 00 3A 00 00 00 00 00
```

첫 번째 줄은 헤더 부분으로 크게 신경써주지 않아도 된다.

두 번째 줄에서 첫 번째 값인 `04`는 변경 해줄 키의 개수이다.

이후부터 각 키의 **Code**를 통해 서로 매핑해주면 되는데 하나씩 살펴보자.

![alt text](assets/img/key_mapping/image_4.png)

[이미지 출처](https://blog.naver.com/minhyupp/222211206474)

`1D 00 5B E0`은 **좌측 윈도우 키(E0 5B)**를 **좌측 Control 키(1D)**로 사용하겠다는 의미이다.

왜냐하면 맥북에서 **Command** 키가 윈도우의 좌측 윈도우 키로 매핑되어 있기 때문에, Command 키를 Control키로 사용하기 위해서 위와 같이 변경해주었다.

`72 00 3A 00`은 **Caps Lock(3A)**를 **한영 키(72)**로 사용하겠다는 의미이다.

왜냐하면 맥북에서 **한/A** 키가 윈도우에서 Caps Lock 키로 매핑되어 있기 때문에, 한/A 키를 한영 키로 사용하기 위해서 위와 같이 변경해주었다.

UTM에서 이 세팅만 해주면, 맥북에서 Caps Lock을 실행하기 위해서 한/A 키를 꾹 눌러줘야 되기 때문에 한영 키 변경이 힘들다.

그래서 UTM 설정에 들어가서 아래와 같이 **Caps Lock is treated as a key**를 체크해주면된다.

![alt text](assets/img/key_mapping/image_5.png)

그러면 맥북의 한/A 키를 꾹 눌러서 Caps Lock이 입력되지 않아도, 맥북에서 한/A키를 누르는 것처럼 Caps Lock 키가 입력되도록 하여 윈도우에서 한영 키를 꾹 누르지 않고 사용할 수 있다.

그리고 참고로, 윈도우 가상 머신 내부에서 크롬과 같은 창을 닫을 때, **Command + W**를 누르면 UTM에서 실행 중인 윈도우 가상 머신 창이 닫혀버릴 수 있다.

이럴 때, **Command + Option**을 누르면 가상 머신의 입력이 호스트 머신으로 전달되지 않아서 윈도우 내부에서 크롬 창을 닫을 때 **Command + W**를 사용할 수 있다.

필자는 위 설정 스크린샷에서 볼 수 있듯이 설정에서 **Control + Option** 대신 **Command + Option**으로 쓰도록 수정해줬지만, 이렇게 해주지 않은 경우 default 로는 **Control + Option**을 해주면 될 것이다.

가상 머신을 실행 중인 창 상단에서 옵션이 active 되어 있는지 확인할 수 있다.