---
title: '[Dreamhack] web-misconf-1'
description: 'Dreamhack [Wargame] - web-misconf-1'
author: juhyeongkim
date: 2024-11-13 04:01:00 +0900
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

[문제 링크](https://dreamhack.io/wargame/challenges/45)

{% raw %}

## 문제 풀이

문제 설명을 살펴보면, 문제에서 제공하는 웹페이지에 접속한 후 `admin` 계정으로 로그인하여 **Organization**에서 플래그를 확인할 수 있다고 한다.

문제에서 제공하는 설정 파일인 `.ini` 파일을 살펴보면, 아래와 같이 쉽게 계정 정보를 확인할 수 있다.

```ini
# default admin user, created on startup
admin_user = admin

# default admin password, can be changed before first start of grafana, or in profile settings
admin_password = admin
```

그리고, 아래와 같이 플래그도 존재하는 것을 확인할 수 있다.

```ini
# specify organization name that should be used for unauthenticated users
org_name = DH{THIS_IS_FAKE_FLAG}
```

따라서 아래와 같이 문제에서 제공하는 웹페이지에서 로그인한 후,

![image](assets/web-misconf-1/image_1.png)

`.ini` 설정 파일이 반영된 **Settings**에 들어가면 `org_name` 필드에서 플래그를 확인할 수 있다.

![image](assets/web-misconf-1/image_2.png)

<br>

**이 문제에서 알려주고자 하는 점은, Grafana 서비스의 초기 default 계정의 `username`과 `password`는 `admin / admin` 이므로 이를 유의해야 한다는 정도인 것 같다.**

{% endraw %}