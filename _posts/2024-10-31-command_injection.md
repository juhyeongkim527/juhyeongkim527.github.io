---
title: Command Injection
description: Dreamhack [Learn] - Command Injection
author: juhyeongkim
date: 2024-10-31 08:00:00 +0900
categories: [Dreamhack, Learn]
tags: [Dreamhack, Learn, Pwnable]
# toc: false
# comments: false
# math: true
# mermaid: true
# image:
#   path: 
#   lqip: 
#   alt: 
---

## 서론

대부분 프로그램을 개발할 때, 처음부터 끝까지 전부 자신의 코드만 사용하기 보다는 이미 존재하는 라이브러리, 소프트웨어 등을 사용하는 경우가 많다.

예를 들어, 파일의 내용을 출력하기 위한 쉘 프로그램을 작성할 때 파일 입출력과 관련된 코드를 전부 작성하기보다는, 시스템에 구현되어 있는 `cat`을 사용하는 게 훨씬 수월하다.

`C/C++`으로 프로그래밍할 때는 이런 경우 `system` 함수를 사용한다. **`system` 함수는 함수에 전달된 인자를 쉘 프로그램에 전달해 명령어를 실행한다.**

즉 `system(“cat /etc/passwd”);`를 호출하면, 쉘에서 `cat /etc/passwd` 명령어를 치는 것과 같은 동작을 하게 된다.

`system` 함수를 사용하면 이미 설치된 소프트웨어들을 쉽게 이용할 수 있다는 장점이 존재하지만, **함수의 인자를 쉘에 직접 전달하기 때문에** 매우 위험한 취약점으로 이어지기도 한다.

이렇게 `system` 함수와 같이 명령어를 실행해주는 함수를 잘못 사용하여 발생하는 취약점을 `Command Injection` 취약점이라고 한다.

<br>

### **int system(const char *command);** 함수가 명령어를 실행하는 과정

1. `system` 함수는 라이브러리 내부에서 `do_system` 함수를 호출한다.

2.  `do_system` 함수는 `sh-c`와 `system` 함수의 인자를 결합하여 `execve` 시스템 콜을 호출한다.

`sh -c`는 `/bin/sh -c`라고 생각하면 되고, `system` 함수는 실패시 `0`을 리턴한다.

<br>

## Command Injection

`인젝션(Injection)` 은 악의적인 데이터를 프로그램에 입력하여 이를 `시스템 명령어`, `코드`, `데이터베이스 쿼리` 등으로 실행되게 하는 기법을 말한다. 

이 중, 사용자의 입력을 시스템 명령어로 실행하게 하는 것을 `Command Injection`이라고 부릅니다. (`SQL Injection`은 DB 쿼리)

이 취약점은 **명령어를 실행하는 함수의 인자를 사용자가 임의로 전달해주거나 수정할 수 있을 때 발생**한다. 앞에서 본 `system` 함수를 사용하면 사용자의 입력을 소프트웨어의 인자로 전달할 수 있다.

예를 들어 사용자가 입력한 임의 `IP`에 `ping`을 전송하고 싶다면 `system("ping [user-input]");`을, 임의 파일을 읽고 싶다면 `system("cat [user-input]");`등의 형태로 `system` 함수를 사용할 수 있다.

그런데 여기서, **사용자의 입력이 악의적인 명령어를 수행하게 하지는 않는지 제대로 검사하지 않으면** 매우 위험한 취약점이 존재한다.

예를 들어 위에서, `[user-input]`의 내용이 `IP 주소`이거나 `파일 이름`만 있다면 상관 없지만, 아래와 같이 메타 문자와 결합하여 쉘을 실행하게 할 수도 있다.

<br>

### 메타 문자

![image](https://github.com/user-attachments/assets/fe8a9c4e-4561-4bbc-9683-6720b29bfe84)

`echo`는 인자로 전달된 문자열을 표준 출력(`stdout`)으로 출력하는 명령어이다. 예외적으로 와일드 카드 `*` 또는 환경 변수 `$`가 사용되면 이를 먼저 해석하여 `echo`에 전달한다.

1. `$`는 쉘에서 `환경 변수`를 참조하는 데 사용된다. `환경 변수`는 시스템의 정보나 사용자 정의 값을 담고 있는 변수이다. 위의 예제에서 `PWD`는 현재 워킹 디렉토리의 경로를 나타낸다.

2. `&&`는 앞의 명령어가 성공적으로 실행된 경우에만 뒤의 명령어를 실행하도록 한다.

3. `;`는 명령어들을 순차적으로 실행한다. 앞의 명령어의 성공 여부와 상관없이 다음 명령어가 실행되는 것이 `&&`와의 차이이다.

4. `|`(파이프)는 앞의 명령어의 출력을 다음 명령어의 입력으로 전달한다. 에시에서 `echo id`의 출력인 `id`를 `/bin/sh`의 입력으로 전달해서 쉘에서 `id` 명령어가 수행되었다.

5. `*`는 파일 이름이나 경로에서 `0개 이상의 문자를 대체`하는 와일드 카드로 사용된다. 예시에서 `.*`는 현재 디렉토리의 모든 숨김 파일을 의미한다.

6. `` ` ``는 `` ` ``로 감싸여진 명령어의 결과가 다른 명령어의 인자로 전달된다. 예시에서 `echo hellotheori`의 결과인 `hellotheori`가 앞의 `echo`에 다시 전달되어 똑같은 출력이 나온다.

여기서 주목할 점은 `&&`, `;`, `|` 를 사용하면 여러 개의 명령어를 연속으로 실행시킬 수 있게 된다는 것이다. 위의 예제에서 `[user-input]`에 IP 주소나 파일 이름을 쓰고, `;`를 붙인 후에 쉘을 실행하는 `/bin/sh`를 붙여주면 `system("/bin/bash");`도 수행되게 된다.

<br>

### 예제

```
// Name: cmdi.c
// Compile: gcc -o cmdi cmdi.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const int kMaxIpLen = 36;
const int kMaxCmdLen = 256;

int main() {
  char ip[kMaxIpLen];
  char cmd[kMaxCmdLen];

  // Initialize local vars
  memset(ip, '\0', kMaxIpLen);
  memset(cmd, '\0', kMaxCmdLen);
  strcpy(cmd, "ping -c 2 ");

  // Input IP
  printf("Health Check\n");
  printf("IP: ");
  fgets(ip, kMaxIpLen, stdin);

  // Construct command
  strncat(cmd, ip, kMaxCmdLen);
  printf("Execute: %s\n",cmd);

  // Do health-check
  system(cmd);

  return 0;
}
```

해당 코드를 보면, 표준 입력을 통해 `kMaxIpLen` 길이 만큼 `ip`에 문자열을 입력할 수 있다. 이후 `strncat(cmd, ip, kMaxCmdLen);`을 통해 `ip`의 내용을 `kMaxCmdLen` 만큼 `cmd` 뒤에 붙여넣기 때문에 `cmd`에 사용자의 입력이 연결되게 된다.

만약 `ip`에 IP 주소를 입력하는 것 뿐만 아니라 `"; /bin/sh"`을 붙여서 입력하게 되면 쉘이 획득되는 취약점 공격이 가능하다.

```
$ ./cmdi
Health Check
IP: 127.0.0.1; /bin/sh
Execute: ping -c 2 127.0.0.1; /bin/sh

PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.020 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.046 ms

--- 127.0.0.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1059ms
rtt min/avg/max/mdev = 0.020/0.033/0.046/0.013 ms
$ id
uid=1000(dreamhack) gid=1000(dreamhack) groups=1000(dreamhack)
```

이를 방지하기 위해 `system` 함수와 같이 소프트웨어에 명령어를 전달하는 함수를 사용하는데, **사용자의 입력을 인자로 사용하는 경우 `메타 문자`의 유무를 철저히 검사해야 한다.**

제일 최선인 것은 정말 중요한 상황이 아니라면 `system` 함수와 같은 성격의 함수를 사용하지 않는 것이 프로그램의 취약점을 제거하는 길이다.