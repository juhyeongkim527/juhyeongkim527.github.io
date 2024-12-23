---
title: '[Dreamhack] SQL Features'
description: 'Dreamhack [Learn] - SQL Features'
author: juhyeongkim
date: 2024-12-24 04:50:00 +0900
categories: [Dreamhack, Learn, Web]
tags: [Dreamhack, Learn, Web]
# toc: false
# comments: false
# math: true
# mermaid: true
# image:
# path: 
    # lqip: 
    # alt: 
---

[강의 링크](https://dreamhack.io/lecture/courses/303)

{% raw %}

## UNION

`UNION` 구문은 **다수의 `SELECT` 구문의 결과를 결합**하는 절이다.

참고로 `SELECT` 구문이 일반적으로 `FROM`, `WHERE` 구문을 포함하지 않고 `SELECT`만 포함한다면 `SELECT` 구문 뒤의 요소들을 각 컬럼으로 가지는 1개의 행을 리턴하게 된다.

예를 들어 `mysql`에서 테스트해보면 아래와 같다.

```sql
mysql> select 'test', 123, 456;
+------+-----+-----+
| test | 123 | 456 |
+------+-----+-----+
| test | 123 | 456 |
+------+-----+-----+
1 row in set (0.00 sec)

mysql> select 'test', 123, 456 union select 'abc', 'def', 123;
+------+-----+-----+
| test | 123 | 456 |
+------+-----+-----+
| test | 123 | 456 |
| abc  | def | 123 |
+------+-----+-----+
2 rows in set (0.00 sec)
```

다시 돌아와서 `UNION` 구문에 대해서 설명하면, 해당 구문을 통해 다른 테이블에 접근하거나 원하는 쿼리 결과를 생성해 애플리케이션에서 처리하는 타 데이터를 조작할 수 있다.

`UNION` 구문은 애플리케이션이 데이터베이스 쿼리의 실행 결과를 출력하는 경우 유용하게 사용할 수 있다.

아래의 예시 구문을 보자.

```sql
mysql> SELECT * FROM UserTable UNION SELECT "DreamHack", "DreamHack PW";

/*
+-----------+--------------+
| username  | password     |
+-----------+--------------+
| admin     | admin        |
| guest     | guest        |
| DreamHack | DreamHack PW |
+-----------+--------------+
3 rows in set (0.01 sec)
*/
```

해당 예시를 보면, `SELECT` 문을 통해 `UserTable`에서 가져온 컬럼은 `username`, `password` 2개이다.

여기서 `UNION`을 통해 `"DreamHack", "DreamHack PW"`을 각 컬럼으로 가지는 1개의 행을 추가하여 `UserTable`에 임의의 값이 추가된 테이블이 반환된 것을 알 수 있다.

<br>

### UNION 구문의 Condition

해당 구문을 사용할 때는 두가지 필수 조건을 만족해야한다.

#### 1. SELECT 구문과 UNION 구문의 실행 결과 중 컬럼의 개수가 같아야 한다.

아래의 예시를 살펴보자.

```sql
mysql> SELECT * FROM UserTable UNION SELECT "DreamHack", "DreamHack PW", "Third Column";

/*
ERROR 1222 (21000): The used SELECT statements have a different number of columns
*/
```
해당 예시를 보면, `UserTable`의 컬럼은 2개인데, `UNION` 구문의 `SELECT` 구문 내에서는 3개의 컬럼을 가지는 1개의 행을 추가한다.

따라서 컬럼의 개수가 맞지 않아서 에러가 뜨게 된다.

<br>

#### 2. 특정 DBMS에서는 이전 SELECT 구문과 UNION 구문을 사용한 구문의 컬럼 타입이 같아야 한다.

아래의 `MSSQL` DBMS의 예시를 보자.

```sql
# MSSQL (SQL Server)
SELECT 'ABC'
UNION SELECT 123;

/*
Conversion failed when converting the varchar value 'ABC' to data type int.
*/
```

해당 예시를 보면, 첫 번째 `SELECT` 구문에서 컬럼의 타입은 `varchar` 인데, 두 번째 `UNION` 구문에서의 컬럼의 타입은 `int`이다.

따라서 두 구문의 데이터 타입이 일치하지 않기 때문에 오류가 발생한다.

<br>

### 실습

![alt text](assets/img/sql_features/image_1.png)

해당 실습에서 관리자 계정의 `upw` 컬럼 값을 출력하려면 어떻게 해야할까 ?

먼저 관리자 계정의 `uid` 컬럼 값을 알아야한다.

이를 위해서는 모든 조건이 `True` 가 되도록 아래와 같이 Login의 uid 필드에 SQL 문을 작성하면 `user_table`의 모든 행에 대한 `uid` 컬럼 값을 알 수 있다.

![alt text](assets/img/sql_features/image_2.png)

그럼 이제, 관리자 계정의 `uid` 컬럼 값이 **admin**임을 유추할 수 있기 때문에, 아래와 같이 `uid` 컬럼 값이 **admin**인 행의 `upw` 컬럼 값을 `UNION` 구문을 통해 읽어오면 될 것이다.

![alt text](assets/img/sql_features/image_3.png)

<br>

## Subquery

서브 쿼리는 한 쿼리 내에서 또 다른 쿼리를 사용하는 것을 의미한다.

서브 쿼리를 사용하기 위해서는 쿼리 내에서 무조건 **괄호 안에 구문을 삽입해야 하며, `SELECT` 구문만 사용할 수 있다.**

공격자는 서브 쿼리를 통해, 

1. 기존 쿼리가 접근하지 않는 다른 쿼리에 접근하거나,

2. `SELECT` 구문을 사용하지 않는 쿼리문에서 `SELECT` 구문을 사용할 수 있다.

아래의 예시를 살펴보자.

```sql
mysql> SELECT 1,2,3,(SELECT 456); 

/*
+---+---+---+--------------+
| 1 | 2 | 3 | (SELECT 456) |
+---+---+---+--------------+
| 1 | 2 | 3 |          456 |
+---+---+---+--------------+
1 row in set (0.00 sec)
*/
```

`UNION` 구문과 달리, 서브 쿼리는 기존 `SELECT` 구문에 **행**을 추가하는 것이 아닌, 서브 쿼리의 결과를 **컬럼**으로 추가한다.

더 많은 아래의 예시를 살펴보자.

```sql
mysql> select * from admin;
+----+--------+--------+----------+--------------------+
| id | aid    | apw    | name     | email              |
+----+--------+--------+----------+--------------------+
|  1 | admin1 | admin1 | Park     | test@gmail.com     |
|  3 | admin2 | admin2 | AdminKim | adminkim@gmail.com |
|  5 | admin3 | admin3 | admin3   | admin3             |
+----+--------+--------+----------+--------------------+
3 rows in set (0.00 sec)

mysql> select aid, (select apw) from admin;
+--------+--------------+
| aid    | (select apw) |
+--------+--------------+
| admin1 | admin1       |
| admin2 | admin2       |
| admin3 | admin3       |
+--------+--------------+
3 rows in set (0.00 sec)

mysql> select aid, (select abc) from admin;
ERROR 1054 (42S22): Unknown column 'abc' in 'field list'

mysql> select aid, (select `apw`) from admin;
+--------+----------------+
| aid    | (select `apw`) |
+--------+----------------+
| admin1 | admin1         |
| admin2 | admin2         |
| admin3 | admin3         |
+--------+----------------+
3 rows in set (0.00 sec)

mysql> select aid, (select 'apw') from admin;
+--------+----------------+
| aid    | (select 'apw') |
+--------+----------------+
| admin1 | apw            |
| admin2 | apw            |
| admin3 | apw            |
+--------+----------------+
3 rows in set (0.00 sec)
```

서브 쿼리는 아래의 규칙에 따라 동작한다.

1. \`\`로 감싸진 컬럼이나, 아예 아무 문자로도 감싸져있지 않은 컬럼이 서브 쿼리의 `SELECT` 구문에 들어가면, 기존 `FROM` 내의 Table에서 컬럼을 찾는다.

2. 서브 쿼리 내의 `''`로 감싸진 컬럼의 경우, `FROM` 내의 Table에서 컬럼을 찾는 것이 아닌, `''`으로 감싸진 컬럼 값 자체를 기존 결과의 각 행에 추가한다.

그럼 서브 쿼리의 사용 예시와 주의점을 하나씩 살펴보자.

### 1. COLUMNS 절

`SELECT` 구문의 컬럼 절에서 서브 쿼리를 사용할 때는 **단일 행, 단일 컬럼**이 반환되도록 해야한다.

```sql
mysql> SELECT username, (SELECT "ABCD" UNION SELECT 1234) FROM users;
ERROR 1242 (21000): Subquery returns more than 1 row

mysql> SELECT username, (SELECT "ABCD", 1234) FROM users;
ERROR 1241 (21000): Operand should contain 1 column(s)
```

위 예시를 보면, 첫 번째 SQL문의 경우 2개의 행을 반환하여 오류가 발생하게 되고, 두 번째 SQL문의 경우 2개의 컬럼을 반환하여 오류가 발생하게 된다.

2개의 행은 아예 사용할 수 없지만, 2개의 컬럼을 사용하고 싶은 경우 서브 쿼리를 2개로 분할하여 사용하면 된다.

<br>

### 2. FROM 절

FROM 절에서 사용하는 서브 쿼리를 **인라인 뷰(Inline View)**라고 하며, 이는 **여러 행과 여러 컬럼** 결과를 반환할 수 있다.


```sql
mysql> select * from (select *, 1234 from admin) as a;
+----+--------+--------+----------+--------------------+------+
| id | aid    | apw    | name     | email              | 1234 |
+----+--------+--------+----------+--------------------+------+
|  1 | admin1 | admin1 | Park     | test@gmail.com     | 1234 |
|  3 | admin2 | admin2 | AdminKim | adminkim@gmail.com | 1234 |
|  5 | admin3 | admin3 | admin3   | admin3             | 1234 |
+----+--------+--------+----------+--------------------+------+
3 rows in set (0.00 sec)
```

<br>

### WHERE 절

`WHERE` 절에서 서브 쿼리를 사용하면 **다중 행** 결과를 반환하는 쿼리문을 실행할 수 있다.

```sql
mysql> SELECT * FROM users WHERE username IN (SELECT "admin" UNION SELECT "guest");
/*
+----------+----------+
| username | password |
+----------+----------+
| admin    | admin    |
| guest    | guest    |
+----------+----------+
2 rows in set (0.00 sec)
*/
```

<br>

## Application Logic

대부분 애플리케이션에서는 특정 SQL 쿼리를 실행했을 때 쿼리의 결과로 다음 로직을 실행하지, 쿼리 실행 결과를 사용자(잠재적인 공격자)에게 보여주는 경우는 드물다.

따라서 공격자는 이러한 경우에 특정 SQL 쿼리의 실행 결과의 **True/False**를 구분하여 SQL Injection 공격을 수행할 수 있다.

아래의 예시 코드를 보자.

```py
## pip3 install PyMySQL //pymysql 라이브러리를 설치하기 위한 명령어

from flask import Flask, request
import pymysql

app = Flask(__name__)

def getConnection():
  return pymysql.connect(host='localhost', user='dream', password='hack', db='dreamhack', charset='utf8')

@app.route('/' , methods=['GET'])
def index():
  username = request.args.get('username')
  sql = "select username from users where username='%s'" %username
  
  conn = getConnection()
  curs = conn.cursor(pymysql.cursors.DictCursor)
  curs.execute(sql)
  rows = curs.fetchall()
  conn.close()
  
  if(rows[0]['username'] == "admin"):
    return "True"
  else:
    return "False"

app.run(host='0.0.0.0', port=8000)
```

해당 코드를 보면, GET 요청에서 `username` 파라미터를 통한 SQL문의 결과로 `username` 컬럼이 반환되는데, 이 컬럼의 값이 `"admin"`인 경우만 `"True"`가 리턴된다.

그럼 해당 SQL 쿼리에 어떤 공격 기법을 활용해 볼 수 있을지 살펴보자.

### 1. UNION

```
/?username=' union select 'admin' --
```

위와 같이 `UNION` 구문을 통해 인자를 전달해서, SQL 쿼리 수행 결과의 `username` 컬럼에 `"admin"`이 포함되도록 할 수도 있다.

사실 `UNION` 없이 그냥 `username`에 바로 `admin`을 넣어도 되긴 한데, `UNION` 사용 예시를 위해 해당 방법을 강의에서 추가한 것 같다.

예를 들어서 만약 위와 같이 예제 코드를 모르는 경우, `union select 1,2,3`과 같이 컬럼 개수를 테스트해볼 수도 있을 것이다.

<br>

### 2. IF, SUBSTR

위에서는 admin 계정의 비밀번호를 알아내는 것까지는 불가능했지만, SQL에서 사용가능한 `if`와 `substr` 함수를 사용하면 admin 계정의 비밀번호를 알아낼 수 있다.

```
if(condition, true_value, false_value)

substr(string, start_position, length)
```

위는 sql의 `if`와 `substr` 함수의 기본형이다. 

`substr` 함수에서 `string`은 비교할 컬럼의 value, `start_position`은 비교 시작점(1부터 시작), `length`는 `string`에서 `=` 뒤의 문자와 비교할 길이이다.

`users` 테이블의 비밀번호를 저장하는 컬럼명이 `password`라고 할 때, 위 구문을 사용하여 비밀번호를 알아내는 쿼리를 작성하면 아래와 같다.

```
/?username=' union select
if(substr(password, 1, 1) = 'P', 'admin', 'not admin')
from users
where username = 'admin' -- - 
...

/?username=' union select
if(substr(password, 2, 1) = 'a', 'admin', 'not admin')
from users
where username = 'admin' -- -
```

먼저, `union` 구문만을 사용한 앞의 예시와 달리, `from`과 `where`가 사용된 이유는 `username = 'admin`인 행의 `password` 컬럼 값을 가져와야하기 때문이다.

위와 같이 `substr` 함수가 참인 경우만 `admin`을 전달하도록 하여, 전체 쿼리 결과가 `"True"`를 반환할 때의 `substr =` 값이 각 자리의 비밀번호가 될 것이닫.

위와 같이 일일히 전달하지 않고, python으로 자동화 스크립트를 작성하면 훨씬 빠르게 비밀번호를 찾아낼 수 있을 것이다.

<br>

### 실습 1.

![alt text](assets/img/sql_features/image_4.png)

위의 모듈 실습을 진행해보자.

먼저 `uid = "admin"`인 행의 비밀번호 첫 글자는 User PW: 필드에 `" or 1 --`를 입력하여 간단하게 **p**인 것을 확인할 수 있다.

![alt text](assets/img/sql_features/image_5.png)

그리고 이제 차례대로 User PW: 필드에 `UNION`과 `SUBSTR`을 사용하여 아래와 같이 비밀번호를 한 글자씩 알아낼 수 있다.

```sql
" union select if(substr(upw, 2, 1) = 'w', "T", "F") from users where uid = "admin" --
```

![alt text](assets/img/sql_features/image_6.png)

참고로, `substr`이 `true`를 리턴할 때, `select if`가 아니라 `select substr`으로 `"t"`가 출력되므로 `if`를 꼭 쓸 필요는 없다.

<br>

### 실습 2.

![alt text](assets/img/sql_features/image_7.png)

해당 실습의 경우, `union`을 쓰려고 하면 `users` 테이블의 컬럼 개수를 알아야 하기 때문에 바로 `union`을 사용하기는 힘들다.

왜냐하면 `select *`를 통해 모든 컬럼을 가져오는데, `users` 테이블의 컬럼 개수를 모르기 때문이다.

그리고 실습 모듈 특성상 `union select 1,2,3 ...` 등으로 컬럼 개수를 파악하려고 해도 제대로 구현이 되어 있지 않아서인지 전부 로그인 성공으로 떠서 컬럼 개수를 알기 힘들다.

이럴 때는 USER PW: 필드에 아래와 같이 `OR` 연산과 `SUBSTR`을 사용하여 조건을 검사할 수 있다.\
(실습 1.에서도 당연히 이 방법으로도 가능하다.)

```sql
" or uid = "admin" and substr(upw, 3, 1) = '3' -- 
```

![alt text](assets/img/sql_features/image_8.png)

참고로 `select` 문에서 `AND`가 `OR`보다 우선순위가 높기 때문에, `OR` 연산이 가장 마지막에 이루어져서 결국 아래와 같은 `select` 문이 수행된다.

```sql
select *
from users 
where (uid="admin" and upw="") or (uid = "admin" and substr(upw, 3, 1) = '3') -- "
```

{% endraw %}