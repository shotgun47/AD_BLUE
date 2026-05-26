## 기본 전송 값
<img width="989" height="163" alt="image" src="https://github.com/user-attachments/assets/141621ce-a526-4b3b-9db5-a10d63ce0ce0" />

* 대상 IP 
    - 기본값 : `.env` 파일의 **VICTIM_URL** 값
    - 대시보드에서 직접 입력해서 변경 가능
* 실행자
    - 기본값 : `.env` 파일의 **ATTACK_REQUESTED_BY** 값
    - 대시보드에서 직접 입력해서 변경 가능


# <환경 세팅>
## ● victim 환경이 도메인에 정상 연결 되었는지 확인
```
whoami
hostname
nltest /dsgetdc:lab.local
Test-ComputerSecureChannel
```

* 예상 기대값 예시
```
LAB\victim3
VICTIM-YB
DC: \\DC01.lab.local  ...
True
```

## ● WinRm 관련 사항
### 활성화
victim 환경 내에서 PowerShell을 관리자 권한으로 실행
(관리자 계정 확인 필요시 디스코드 참고 - `lab_admin` 계정)

```
Enable-PSRemoting -Force
```

* 서비스 상태 확인
```
Get-Service WinRM
```
Running 이면 정상

### 상태 확인
victim 환경 내에서 PowerShell을 관리자 권한으로 실행
(관리자 계정 확인 필요시 디스코드 참고 - `lab_admin` 계정)

```
winrm enumerate winrm/config/listener
```
혹은
```
Test-WSMan localhost
```

둘다 아래 관련 정보가 정상적으로 출력되어야 함

### 포트 확인
```
netstat -ano | findstr :5985
```
LISTENING 상태여야 함

### 일반 사용자 등록
(ex) LAB\victim3 으로 시도하려면
```
net localgroup "Remote Management Users" "LAB\victim3" /add
```

* 정상 등록 확인
```
net localgroup "Remote Management Users"
```
'구성원' 항목에 등록한 계정이 보여야 함

## ● PowerShell 관련 사항
### auditpol 옵션 켜기 (감사정책)
* 항목 이름 확인
```
auditpol /get /category:* | Select-String -Pattern "프로세스|Process|상세|Detailed"
```

아마 "프로세스 만들기" 로 되어있을것

```
auditpol /set /subcategory:"프로세스 만들기" /success:enable /failure:enable
```

다시 `auditpol /get ~` 로 확인했을때 "프로세스 만들기" 항목이   "성공" 으로 뜨면 ok 


---
# <공격 시나리오>
# 1. 4625 로그인 실패 / 실패 급증
잘못된 SMB 인증을 반복해서 Windows 보안 로그에 로그인 실패 이벤트 발생시킴.

* 대상 : `victim`
* 사용 도구(공격머신) : `smbclient`

## 입력 파라미터
(ex) LAB\victim3 로그인 실패 시도 

* 도메인 : `LAB`
* 사용자명 : `victim3` 혹은 가짜 이름 `fakeuser`
* 비밀번호 : 실패할 비밀번호
* 시도횟수 : 10 (현재 탐지 룰 기준)
* 시도간격(초) : 3~5

## 타겟 환경 사전 세팅
* 445 포트 접근 가능
* Winlogbeat가 Security 로그 전송

## 탐지 기대 로그
* 4625 | login_faiure

---

# 2. 패스워드 스프레이
여러 계정에 동일한 비밀번호를 순차적으로 시도.

* 대상 : `victim`
* 사용 도구(공격머신) : `nxc (SMB/WinRM 인증 시도)`


## 입력 파라미터
(ex) LAB\victim1-4 로그인 시도

* 도메인 : `LAB`
* 대상 계정 목록 : `victim1,victim2,victim3,victim4`
* 시도할 비밀번호 : 시도할 비밀번호. 정상 비밀번호면 성공, 틀린값이면 실패
* 인증 프로토콜 : `winrm` (smb는 망 상태가 불안하면 연결 실패가 자주 발생함. winrm 이 안정적)

## 타겟 환경 사전 세팅
* 시도할 계정 목록이 원격 접속 사용자 권한 부여 완료 되어있어야 함

## 탐지 기대 로그
* 4625 로그인 실패
* 4776 SMB 관련 (smb 프로토콜 사용했을 경우)
* 4624 로그인 성공
* 원격 로그인 관련

---

# 3. PowerShell 실행 테스트 4688

* 대상 : `victim`
* 사용 도구(공격머신) : `Impacket(wmiexec)`

## 입력 파라미터
WMI 원격 실행을 위해 관리자 권한이 있는 계정(ex : `lab_admin`)이어야 실행 가능.

* 도메인 : `LAB`
* 계정명 : `lab_admin`
* 비밀번호 : 디스코드 참고

## 타겟 환경 사전 세팅
* 감사 정책

## 탐지 기대 로그
* 4688 프로세스 생성 + 프로세스명 powershell.exe
* 1
* 탐지 룰 : 041, 042, 015

---

# 4. PowerView

* 대상 : `victim`
* 사용 도구(공격머신) : `evil-winrm`


## 입력 파라미터
(ex) victim3 계정으로 로그인

* 사용자 : `victim3`
* 비밀번호 : 정상 비밀번호
* 도메인 이름 : `lab.local` 

## 타겟 환경 사전 세팅
* WinRM 활성화
* Remote Management Users 그룹
* PowerView 경로 : `C:\Tools\PowerView\` (고정값. 반드시 이 경로에 있어야 함)
```
C:\Tools\PowerView\
  ├─ PowerView.ps1
  └─ pv_recon.ps1
```

두 파일 다 `attack_scenarios/PowerView` 경로에 올라가 있는데
`pv_recon.ps1.txt` 파일은 그대로 복사해서 .txt 만 지우고 사용하면 되고
`PowerView.ps1`.txt` 파일은 안에 있는 링크 들어가서 내용 그대로 복사해서 사용하면 됩니다

* 파워쉘에서 PowerView 경로 Defender 예외 등록 : 안하면 자꾸 파일 지워짐,, 
```
Add-MpPreference -ExclusionPath "C:\Tools\PowerView"
```

## 탐지 기대 로그
* 4688
