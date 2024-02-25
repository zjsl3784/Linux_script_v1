#!/bin/sh


echo "전역변수 검사를 진행하시겠습니까? ( 예시: find / 사용)"
echo "해당 항목은 점검 시 과부하가 발생될 수 있습니다. 운영중인 서버인 경우 진행하지 않는 것을 권고드립니다."
echo "진행하지 않을 경우 U-06, U-15, U-59 항목은 N/A 처리 됩니다."
echo " "
while true; do
    read -p "진행 여부 입력 (y/n): " wwd
    if [[ "$wwd" == "Y" || "$wwd" == "y" ]]; then
        echo "전역변수 검사를 수행합니다. 다소 시간이 소요될 수 있음"
        break
    elif [[ "$wwd" == "N" || "$wwd" == "n" ]]; then
        echo "전역변수 검사를 수행하지 않습니다."
        break
    else
        echo "잘못된 입력입니다. 'y' 또는 'n'을 입력하세요."
    fi
done


Mk="Result_file_"`hostname`_`date +%y%m%d`.xml
echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" > $Mk 2>&1
echo "<rows>" >> $Mk 2>&1

echo " "
echo "================================================================================"
echo "===   2021 KISA 주요정보통신기반시설 기술적 취약점 분석/평가 가이드 기준     ==="
echo "================================================================================"
echo "==                                                                            =="
echo "==                       < Linux 진단 스크립트 >                              =="
echo "==                                                                            =="
echo "==  Made by 박수현                                                            =="
echo "==  feedback email : qkrtngus211@naver.com                                    =="
echo "==  Version : 1.01v                                                            =="
echo "==                                                                            =="
echo "================================================================================"
u06file=0
u15file=0
u59file=0

chk() {
	if [ $1 == 0 ]; then chkk="양호"
	elif [ $1 == 2 ]; then chkk="수동확인 필요"
	elif [ $1 == 3 ]; then chkk="N/A"
	elif [ $1 == 1 ]; then chkk="취약"
	elif [ $1 == 4 ]; then chkk="인터뷰"
	fi

}

INF(){
chk 0
echo "  <row>" >> $Mk 2>&1
echo "    <분류>Info</분류>" >> $Mk 2>&1
echo "    <점검항목>" >> $Mk 2>&1  
echo "점검 기준 : " >> $Mk 2>&1
echo "KISA 2021 주요정보통신기반시설 기술적 취약점 분석 평가 방법 상세가이드" >> $Mk 2>&1
echo "</점검항목>" >> $Mk 2>&1
echo "    <주통코드> " >> $Mk 2>&1
echo "점검 대상 : "  >> $Mk 2>&1
echo "`hostname`"  >> $Mk 2>&1
echo "</주통코드>" >> $Mk 2>&1
echo "<위험도>" >> $Mk 2>&1
echo "호스트 IP : " >> $Mk 2>&1
echo "`hostname -I | awk '{print $1}'`" >> $Mk 2>&1
echo "</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo " OS정보 : "  >> $Mk 2>&1
echo "`cat /etc/*-release |grep -v "ANSI" |grep -v "URL"`" >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>">> $Mk 2>&1
echo "점검일자 :" >> $Mk 2>&1
echo "`date`" >> $Mk 2>&1
echo " </결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
echo " " >> $Mk 2>&1
}


U01() {
chk 0
echo "================================ S T A R T ====================================="
echo "== [U-01]  root 계정 원격접속 제한 ============================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>계정관리</분류>" >> $Mk 2>&1
echo "    <점검항목>root 계정 원격 접속 제한</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-01</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 원격 터미널 서비스를 사용하지 않거나, 사용 시  root 직접 접속을 차단한 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
if [ `systemctl status telnet.socket 2>/dev/null | wc -l` -gt 0 ]; then
	echo "[ telnet 서비스 실행 중 ]" >> $Mk 2>&1 
	echo "`ps -ef | grep "telnetd" | grep -v "grep"`" >> $Mk 2>&1 
		if [ `cat /etc/securetty | grep "pts" | grep -v "#" | wc -l` -gt 0 ]; then chk 1
			 echo "/etc/securetty 파일에 pts 설정이 존재함 (취약)" >> $Mk 2>&1 
			 echo "`cat /etc/securetty | grep "pts"`" >> $Mk 2>&1
	 	fi
		if [ `cat /etc/pam.d/login | grep "pam_securetty.so" | grep "#" | wc -l` -gt 0 ]; then chk 1
			 echo "/etc/pam.d/login 파일  확인필요" >> $Mk 2>&1 
			 echo "`cat /etc/pam.d/login | grep "pam_securetty.so"`" >> $Mk 2>&1
		fi
else echo "[ telnet 서비스 미사용 ]" >> $Mk 2>&1
fi
echo "" >> $Mk 2>&1

if [ `ps -ef | grep "sshd" | grep -v "grep" | wc -l` -gt 0 ]; then
	echo "[ SSH 서비스 실행 중 ]" >> $Mk 2>&1
	echo "`ps -ef | grep "sshd" | grep -v "grep"`" >> $Mk 2>&1
		if [ `cat /etc/ssh/sshd_config | grep "PermitRootLogin" | grep "yes" | grep "#" | wc -l` -gt 0 ]; then chk 1
			echo " " >> $Mk 2>&1
			echo "[ /etc/ssh/sshd_config 설정 값 ]" >> $Mk 2>&1
			echo "`cat /etc/ssh/sshd_config | grep "PermitRootLogin" | grep "yes" | grep "#"`" >> $Mk 2>&1
			echo " " >> $Mk 2>&1
			echo "PermitRootLogin 설정이 주석처리된 경우 root 원격 로그인이 허용됨(취약)" >> $Mk 2>&1
		fi
		if [ `cat /etc/ssh/sshd_config | grep "PermitRootLogin" | grep "yes" | grep -v "#" | wc -l` -gt 0 ]; then chk 1
			echo " " >> $Mk 2>&1
			echo "[ /etc/ssh/sshd_config 설정 값 ]" >> $Mk 2>&1
			echo "`cat /etc/ssh/sshd_config | grep "PermitRootLogin" | grep "yes" | grep -v "#"`" >> $Mk 2>&1
			echo " " >> $Mk 2>&1
			echo "PermitRootLogin 설정이 허용됨 (취약)" >> $Mk 2>&1
		else echo "SSH 서비스가 실행중이나 Root 로그인이 차단됨 (양호)" >> $Mk 2>&1
		fi
else echo "[ ssh 서비스 미사용 ]" >> $Mk 2>&1 
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U02() {
chk 0
echo "== [U-02]  패스워드 복잡성 설정  ==============================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>계정관리</분류>" >> $Mk 2>&1
echo "    <점검항목>패스워드 복잡성 설정</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-02</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 패스워드 최소길이 8자리 이상, 영문 숫자 특수문자 최소 입력 기능이 설정된 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
if [ -e /etc/security/pwquality.conf ]; then
	echo "[ /etc/security/pwquality.conf 설정 값 ]" >> $Mk 2>&1
	echo "`cat /etc/security/pwquality.conf | grep "lcredit"`" >> $Mk 2>&1
	echo "`cat /etc/security/pwquality.conf | grep "ucredit"`" >> $Mk 2>&1
	echo "`cat /etc/security/pwquality.conf | grep "dcredit"`" >> $Mk 2>&1
	echo "`cat /etc/security/pwquality.conf | grep "ocredit"`" >> $Mk 2>&1
	echo "`cat /etc/security/pwquality.conf | grep "minlen"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	if [ `cat /etc/security/pwquality.conf | grep "lcredit" | grep "#" | wc -l` -gt 0 ]; then chk 1 
	fi
	if [ `cat /etc/security/pwquality.conf | grep "ucredit" | grep "#" | wc -l` -gt 0 ]; then chk 1 
	fi	
	if [ `cat /etc/security/pwquality.conf | grep "dcredit" | grep "#" | wc -l` -gt 0 ]; then chk 1 
	fi
	if [ `cat /etc/security/pwquality.conf | grep "ocredit" | grep "#" | wc -l` -gt 0 ]; then chk 1  
	fi	
	if [ `cat /etc/security/pwquality.conf | grep "minlen" | grep "#" | wc -l` -gt 0 ]; then chk 1  
	fi

	if [ `cat /etc/security/pwquality.conf | grep "lcredit" | awk -F'=' '{print $2}'` -gt 0 ]; then chk 1  
	fi
	if [ `cat /etc/security/pwquality.conf | grep "ucredit" | awk -F'=' '{print $2}'` -gt 0 ]; then chk 1  
	fi
	if [ `cat /etc/security/pwquality.conf | grep "dcredit" | awk -F'=' '{print $2}'` -gt 0 ]; then chk 1  
	fi
	if [ `cat /etc/security/pwquality.conf | grep "ocredit" | awk -F'=' '{print $2}'` -gt 0 ]; then chk 1  
	fi
	if [ `cat /etc/security/pwquality.conf | grep "minlen" | awk -F'=' '{print $2}'` -le 7 ]; then chk 1  
	fi

	if [ $chkk = "취약" ]; then 
		echo " " >> $Mk 2>&1
		echo "설정값이 주석처리 되어 있거나 부적절한 설정입니다. (취약)" >> $Mk 2>&1
		echo "KISA 권장값 : lcredit -1, ucredit -1, dcredit -1, ocredit -1, minlen 8이상  " >> $Mk 2>&1
		else echo "패스워드 복잡성 설정이 적절합니다. (양호)" >> $Mk 2>&1
	fi
else echo "/etc/security/pwquality.conf 파일이 존재하지 않습니다. 현재 스크립트는 CentOS7 기준으로 타 버전은 후에 추가될 예정입니다. (해당 항목은 수동확인 필요)" >> $Mk 2>&1
chk 2
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
echo " " >> $Mk 2>&1
}


U03() {
chk 0
echo "== [U-03]  계정 잠금 임계값 설정 ==============================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>계정관리</분류>" >> $Mk 2>&1
echo "    <점검항목>계정 잠금 임계값 설정</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-03</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 계정 잠금 임계값이 10회 이하의 값으로 설정되어 있는 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

if [ `cat /etc/pam.d/system-auth | grep "pam_tally" | grep "deny" | wc -l` -eq 0 ]; then chk 1
	echo "[ /etc/pam.d/system-auth 설정 값 ]" >> $Mk 2>&1
	echo "`cat /etc/pam.d/system-auth | grep "auth" | grep "required"`" >> $Mk 2>&1
	echo "`cat /etc/pam.d/system-auth | grep "account" | grep "required"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	echo "계정 잠금 임계값 설정이 존재하지 않음. (취약)" >> $Mk 2>&1

	elif [ `cat /etc/pam.d/system-auth | grep "pam_tally" | grep "auth" | grep "required" | awk -F'deny=' '{print $2}' | awk '{print $1}'` -gt 10 ]; then chk 1
		echo "[ /etc/pam.d/system-auth 설정 값 ]" >> $Mk 2>&1
		echo "`cat /etc/pam.d/system-auth | grep "pam_tally" | grep "auth" | grep "required"`" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		echo "계정 잠금 임계값 설정이 10회 초과임. (취약)" >> $Mk 2>&1
		echo "KISA 권고 10회 이하" >> $Mk 2>&1
else 
	echo "[ /etc/pam.d/system-auth 설정 값 ]" >> $Mk 2>&1
	echo "`cat /etc/pam.d/system-auth | grep "pam_tally" | grep "auth" | grep "required"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	echo "계정  잠금 임계값 설정이 적절함. (양호)"  >> $Mk 2>&1
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
echo " " >> $Mk 2>&1
}


U04() {
chk 0
echo "== [U-04]  패스워드 파일 보호   ================================================"
echo "  <row>" >> $Mk 2>&1
echo "    <분류>계정관리</분류>" >> $Mk 2>&1
echo "    <점검항목>패스워드 파일 보호</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-04</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 쉐도우 패스워드를 사용하거나, 패스워드를 암호화하여 저장하는 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1


if [ `cat /etc/passwd | awk -F: '{print $2}' | grep -v "x" | wc -l` -gt 0 ]; then chk 1
	echo "[ /etc/passwd 설정 값 ]" >> $Mk 2>&1
	echo "`head -5 /etc/passwd`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1	
	echo "쉐도우 패스워드 사용중이 아님 (취약) " >> $Mk 2>&1
else 
	echo "[ /etc/passwd 값 ]"  >> $Mk 2>&1
	echo "`head -5 /etc/passwd`"	 >> $Mk 2>&1
	echo " " >> $Mk 2>&1	
	echo "패스워드 암호화 사용중 (양호)" >> $Mk 2>&1
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
echo " " >> $Mk 2>&1
}


U05() {
chk 0
echo "== [U-05]  Root홈, 패스 디렉터리 권한 및 패스 설정   ==========================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>파일 및 디렉토리 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>Root홈, 패스 디렉터리 권한 및 패스 설정</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-05</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : PATH 환경변수에 '.'이 맨 앞이나 중간에 포함되지 않은 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

echo "[ 환경변수 정보 ]" >> $Mk 2>&1
echo "`echo $PATH`" >> $Mk 2>&1
echo "" >> $Mk 2>&1
if [ `echo $PATH | rev | cut -c 2- | rev | grep "\." | wc -l` -gt 0 ]; then chk 1
	echo "환경변수에 '.' 이 맨 앞이나 중간에 존재함 (취약)" >> $Mk 2>&1
else 
	echo "환경변수에 '.' 이 맨 앞이나 중간에 포함되지 않음 (양호)" >> $Mk 2>&1
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U06() {
chk 0
rm -rf ./U-06_info.txt
if [[ "$wwd" == "Y" || "$wwd" == "y" ]]; then
	echo "== [U-06]  파일 및 디렉터리 소유자 설정   ======================================"
else
	echo "== [U-06]  파일 및 디렉터리 소유자 설정   =================[ N/A ]=============="
fi
echo "  <row>" >> $Mk 2>&1
echo "    <분류>파일 및 디렉토리 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>파일 및 디렉터리 소유자 설정</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-06</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않는 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
if [[ "$wwd" == "Y" || "$wwd" == "y" ]]; then
	find / -nouser -print >> ./U06_1.txt 2>&1
	echo "소유자가 없는 파일 :"  >> $Mk 2>&1
	if [ `head -10 ./U06_1.txt | grep -v "find" | wc -l` -gt 0 ]; then chk 1
		echo "`tail -n 5 ./U06_1.txt`" >> $Mk 2>&1
		echo "소유자가 없는 파일이 존재함. (최대 5줄 출력) (취약)" >> $Mk 2>&1
		echo "상세 내용은 U-06_info 파일 참조" >> $Mk 2>&1
	else
		echo "소유자가 없는 파일이 존재하지 않음 (양호)" >> $Mk 2>&1
	fi
	touch ./U-06_info.txt
	echo "소유자가 없는 파일목록 (nouser) :" >> ./U-06_info.txt 2>&1
	cat U06_1.txt | grep -v "find" >> ./U-06_info.txt
	rm -rf ./U06_1.txt

	echo " " >> ./U-06_info.txt 2>&1
	echo "###########################################################" >> ./U-06_info.txt 2>&1
	echo " " >> ./U-06_info.txt 2>&1
	echo "그룹이 없는 파일목록 (nogroup) : " >> ./U-06_info.txt 2>&1

	echo " " >> $Mk 2>&1
	echo "그룹이 없는 파일 :" >> $Mk 2>&1
	find / -nogroup -print >> ./U06_2.txt 2>&1

	if [ `head -10 ./U06_2.txt | grep -v "find" | wc -l` -gt 0 ]; then chk 1
		echo "`tail -n 5 ./U06_2.txt`"  >> $Mk 2>&1
		echo "그룹이 없는 파일이 존재함. (최대 5줄 출력) (취약)" >> $Mk 2>&1
		echo "상세 내용은 U-06_info 파일 참조" >> $Mk 2>&1
	else
		echo "그룹이 없는 파일이 존재하지 않음 (양호)" >> $Mk 2>&1
	fi
	
	cat ./U06_2.txt | grep -v "find" >> ./U-06_info.txt
	rm -rf ./U06_2.txt
	if [ `head -10 ./U-06_info.txt | wc -l` -le 5 ]; then 
		rm -rf ./U-06_info.txt
	else
		u06file=+1
	fi
else	
	echo "전역변수 검사를 선택하지 않음 (N/A)" >> $Mk 2>&1
	chk 3
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U07() {
chk 0
aaa=0
echo "== [U-07]  /etc/passwd 파일 소유자 및 권한 설정  ==============================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>파일 및 디렉토리 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>/etc/passwd 파일 소유자 및 권한 설정</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-07</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : /etc/passwd 파일의 소유자가 root이고, 권한이 644 이하인 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
echo "`ls -al /etc/passwd`" >> $Mk 2>&1
echo " " >> $Mk 2>&1
if [ `ls -al /etc/passwd | awk -F' ' '{print $3}' | grep "root" | wc -l` -gt 0 ]; then
	echo "/etc/passwd 파일의 소유자가 root임 (양호)" >> $Mk 2>&1
else
	chk 1
	echo "/etc/passwd 파일의 소유자가 root가 아님 (취약)" >> $Mk 2>&1
fi

if [ `stat -L -c '%a' /etc/passwd | cut -c 1` -gt 6 ]; then chk 1
	aaa=+1
fi
if [ `stat -L -c '%a' /etc/passwd | cut -c 2` -gt 4 ]; then chk 1
	aaa=+1
fi
if [ `stat -L -c '%a' /etc/passwd | cut -c 3` -gt 4 ]; then chk 1
	aaa=+1
fi
if [ $aaa != 0 ]; then 
	echo "부적절한 퍼미션 사용중. 644이하 권장 (취약)" >> $Mk 2>&1
else
	echo "적절한 퍼미션 사용 (양호)" >> $Mk 2>&1
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U08() {
chk 0
aaa=0
echo "== [U-08]  /etc/shadow 파일 소유자 및 권한 설정  ==============================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>파일 및 디렉토리 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>/etc/shadow 파일 소유자 및 권한 설정</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-08</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : /etc/shadow 파일의 소유자가 root이고, 권한이 400 이하인 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
echo "`ls -al /etc/shadow`" >> $Mk 2>&1
echo " " >> $Mk 2>&1

if [ `ls -al /etc/shadow | awk -F' ' '{print $3}' | grep "root" | wc -l` -gt 0 ]; then
	echo "/etc/shadow 파일의 소유자가 root임 (양호)" >> $Mk 2>&1
else
	chk 1
	echo "/etc/shadow 파일의 소유자가 root가 아님 (취약)" >> $Mk 2>&1
fi

if [ `stat -L -c '%a' /etc/shadow` -eq 0 ]; then
	echo "적절한 퍼미션 사용 (양호)" >> $Mk 2>&1
else
	if [ `stat -L -c '%a' /etc/shadow | cut -c 1` -gt 4 ]; then chk 1
		aaa=+1
	fi
	if [ `stat -L -c '%a' /etc/shadow | cut -c 2` -gt 0 ]; then chk 1
		aaa=+1
	fi
	if [ `stat -L -c '%a' /etc/shadow | cut -c 3` -gt 0 ]; then chk 1
		aaa=+1
	fi
	if [ $aaa != 0 ]; then 
		echo "부적절한 퍼미션 사용중. 400이하 권장 (취약)" >> $Mk 2>&1
	else
		echo "적절한 퍼미션 사용 (양호)" >> $Mk 2>&1
	fi
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U09() {
chk 0
aaa=0
echo "== [U-09]  /etc/hosts 파일 소유자 및 권한 설정 ================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>파일 및 디렉토리 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>/etc/hosts 파일 소유자 및 권한 설정</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-09</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : /etc/hosts 파일의 소유자가 root이고, 권한이 600 이하인 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
echo "`ls -al /etc/hosts`" >> $Mk 2>&1
echo " " >> $Mk 2>&1

if [ `ls -al /etc/hosts| awk -F' ' '{print $3}' | grep "root" | wc -l` -gt 0 ]; then
	echo "/etc/hosts파일의 소유자가 root임 (양호)" >> $Mk 2>&1
else
	chk 1
	echo "/etc/hosts 파일의 소유자가 root가 아님 (취약)" >> $Mk 2>&1
fi

if [ `stat -L -c '%a' /etc/hosts | cut -c 1` -gt 6 ]; then chk 1
	aaa=+1
fi
if [ `stat -L -c '%a' /etc/hosts | cut -c 2` -gt 0 ]; then chk 1
	aaa=+1
fi
if [ `stat -L -c '%a' /etc/hosts | cut -c 3` -gt 0 ]; then chk 1
	aaa=+1
fi
if [ $aaa != 0 ]; then 
	echo "부적절한 퍼미션 사용중. 600이하 권장 (취약)" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	echo "※ 주의 : 해당 항목은 KISA에서 600 이하 퍼미션을 권장하고있지만, 실제 600으로 변경시 여러 서비스에 영향을 줄 가능성이 매우 큰 항목입니다. 충분한 검토 및 테스트 이후 적용하는 것을 권장드립니다." >> $Mk 2>&1
else
	echo "적절한 퍼미션 사용 (양호)" >> $Mk 2>&1
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U10() {
aaa=0
chk 0
echo "== [U-10]  /etc/(x)inetd.conf 파일 소유자 및 권한 설정 ========================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>파일 및 디렉토리 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>/etc/(x)inetd.conf 파일 소유자 및 권한 설정</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-10</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : /etc/inetd.conf 파일의 소유자가 root이고, 권한이 600 이하인 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
echo " " >> $Mk 2>&1

if [ -e /etc/inetd.conf ] || [ -e /etc/xinetd.conf ]; then
	echo "(x)inetd 슈퍼데몬 파일이 존재함"	>> $Mk 2>&1
else 
	echo "/etc/inetd.conf 또는 /etc/xinetd.conf 파일이 존재하지 않음" >> $Mk 2>&1
	echo "(x)inetd 슈퍼데몬을 사용하지 않음 (N/A)" >> $Mk 2>&1
	chk 3
fi		


if [ -e /etc/inetd.conf ]; then
	echo "`ls -al /etc/inetd.conf`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	if [ `ls -al /etc/inetd.conf| awk -F' ' '{print $3}' | grep "root" | wc -l` -gt 0 ]; then
		echo "/etc/inetd.conf 파일의 소유자가 root임 (양호)" >> $Mk 2>&1
	else
		chk 1
	echo "/etc/inetd.conf 파일의 소유자가 root가 아님 (취약)" >> $Mk 2>&1
	fi
fi 

if [ -e /etc/xinetd.conf ]; then
	echo "`ls -al /etc/xinetd.conf`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	if [ `ls -al /etc/xinetd.conf| awk -F' ' '{print $3}' | grep "root" | wc -l` -gt 0 ]; then
		echo "/etc/xinetd.conf 파일의 소유자가 root임 (양호)" >> $Mk 2>&1
	else
		chk 1
	echo "/etc/xinetd.conf 파일의 소유자가 root가 아님 (취약)" >> $Mk 2>&1
	fi
fi 


if [ -e /etc/inetd.conf ]; then
	if [ `stat -L -c '%a' /etc/inetd.conf | cut -c 1` -gt 6 ]; then chk 1
		aaa=+1
	fi
	if [ `stat -L -c '%a' /etc/inetd.conf | cut -c 2` -gt 0 ]; then chk 1
		aaa=+1
	fi
	if [ `stat -L -c '%a' /etc/inetd.conf | cut -c 3` -gt 0 ]; then chk 1
		aaa=+1
	fi
	if [ $aaa != 0 ]; then 
		echo "부적절한 퍼미션 사용중. 600이하 권장 (취약)" >> $Mk 2>&1
	else
		echo "적절한 퍼미션 사용 (양호)" >> $Mk 2>&1
	fi
fi


if [ -e /etc/xinetd.conf ]; then
	if [ `stat -L -c '%a' /etc/xinetd.conf | cut -c 1` -gt 6 ]; then chk 1
		aaa=+1
	fi
	if [ `stat -L -c '%a' /etc/xinetd.conf | cut -c 2` -gt 0 ]; then chk 1
		aaa=+1
	fi
	if [ `stat -L -c '%a' /etc/xinetd.conf | cut -c 3` -gt 0 ]; then chk 1
		aaa=+1
	fi
	if [ $aaa != 0 ]; then 
		echo "부적절한 퍼미션 사용중. 600이하 권장 (취약)" >> $Mk 2>&1
	else
		echo "적절한 퍼미션 사용 (양호)" >> $Mk 2>&1
	fi
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U11() {
aaa=0
chk 0
echo "== [U-11]  /etc/syslog.conf 파일 소유자 및 권한 설정 ==========================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>파일 및 디렉토리 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>/etc/syslog.conf 파일 소유자 및 권한 설정</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-11</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : /etc/syslog.conf 파일의 소유자가 root이고, 권한이 640 이하인 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
echo " " >> $Mk 2>&1

	

if [ -e /etc/syslog.conf ]; then
	echo "`ls -al /etc/syslog.conf`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	if [ `ls -al /etc/syslog.conf| awk -F' ' '{print $3}' | grep "root" | wc -l` -gt 0 ]; then
		echo "/etc/syslog.conf 파일의 소유자가 root임 (양호)" >> $Mk 2>&1
	else
		chk 1
	echo "/etc/syslog.conf 파일의 소유자가 root가 아님 (취약)" >> $Mk 2>&1
	fi
fi 

if [ -e /etc/rsyslog.conf ]; then
	echo "`ls -al /etc/rsyslog.conf`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	if [ `ls -al /etc/rsyslog.conf| awk -F' ' '{print $3}' | grep "root" | wc -l` -gt 0 ]; then
		echo "/etc/rsyslog.conf 파일의 소유자가 root임 (양호)" >> $Mk 2>&1
	else
		chk 1
	echo "/etc/rsyslog.conf 파일의 소유자가 root가 아님 (취약)" >> $Mk 2>&1
	fi
fi 




if [ -e /etc/syslog.conf ]; then
	if [ `stat -L -c '%a' /etc/syslog.conf | cut -c 1` -gt 6 ]; then chk 1
		aaa=+1
	fi
	if [ `stat -L -c '%a' /etc/syslog.conf | cut -c 2` -gt 4 ]; then chk 1
		aaa=+1
	fi
	if [ `stat -L -c '%a' /etc/syslog.conf | cut -c 3` -gt 0 ]; then chk 1
		aaa=+1
	fi
	if [ $aaa != 0 ]; then 
		echo "부적절한 퍼미션 사용중. 640이하 권장 (취약)" >> $Mk 2>&1
	else
		echo "적절한 퍼미션 사용 (양호)" >> $Mk 2>&1
	fi
fi


if [ -e /etc/rsyslog.conf ]; then
	if [ `stat -L -c '%a' /etc/rsyslog.conf | cut -c 1` -gt 6 ]; then chk 1
		aaa=+1
	fi
	if [ `stat -L -c '%a' /etc/rsyslog.conf | cut -c 2` -gt 4 ]; then chk 1
		aaa=+1
	fi
	if [ `stat -L -c '%a' /etc/rsyslog.conf | cut -c 3` -gt 0 ]; then chk 1
		aaa=+1
	fi
	if [ $aaa != 0 ]; then 
		echo "부적절한 퍼미션 사용중. 640이하 권장 (취약)" >> $Mk 2>&1
	else
		echo "적절한 퍼미션 사용 (양호)" >> $Mk 2>&1
	fi
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U12() {
aaa=0
chk 0
echo "== [U-12]  /etc/services 파일 소유자 및 권한 설정 =============================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>파일 및 디렉토리 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>/etc/services 파일 소유자 및 권한 설정</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-12</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : /etc/services 파일의 소유자가 root이고, 권한이 644 이하인 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
echo " " >> $Mk 2>&1

echo "`ls -al /etc/services`" >> $Mk 2>&1
echo " " >> $Mk 2>&1
if [ `ls -al /etc/services| awk -F' ' '{print $3}' | grep "root" | wc -l` -gt 0 ]; then
	echo "/etc/services 파일의 소유자가 root임 (양호)" >> $Mk 2>&1
else
	chk 1
	echo "/etc/services 파일의 소유자가 root가 아님 (취약)" >> $Mk 2>&1
fi 

if [ `stat -L -c '%a' /etc/services | cut -c 1` -gt 6 ]; then chk 1
	aaa=+1
fi
if [ `stat -L -c '%a' /etc/services | cut -c 2` -gt 4 ]; then chk 1
	aaa=+1
fi
if [ `stat -L -c '%a' /etc/services | cut -c 3` -gt 4 ]; then chk 1
	aaa=+1
fi
if [ $aaa != 0 ]; then 
	echo "부적절한 퍼미션 사용중. 644이하 권장 (취약)" >> $Mk 2>&1
else
	echo "적절한 퍼미션 사용 (양호)" >> $Mk 2>&1
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U13() {
rm -rf ./U13.txt
rm -rf ./U13_1.txt
chk 0
echo "== [U-13]  SUID, SGID 설정 파일점검 ============================================"
echo "  <row>" >> $Mk 2>&1
echo "    <분류>파일 및 디렉토리 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>SUID, SGID 설정 파일점검</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-13</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 주요 실행파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않은 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
echo " " >> $Mk 2>&1
touch ./U13.txt
find / -user root -type f \( -perm -04000 -o -perm -02000 \) -exec ls -al {} \; >> ./U13.txt 2>&1
cat ./U13.txt | grep -E "/sbin/dump|/sbin/restore|/sbin/unix_chkpwd|/usr/bin/at|/usr/bin/lpq|/usr/bin/lpq-lpd|/usr/bin/lpr|/usr/bin/lpr-lpd|/usr/bin/lprm|/usr/bin/lprm-lpd|/usr/bin/newgrp|/usr/sbin/lpc|/usr/sbin/lpc-lpd|/usr/sbin/traceroute" >> ./U13_1.txt

if [ `head -10 ./U13_1.txt | wc -l` -gt 0 ]; then
	echo "`cat ./U13_1.txt`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	echo "SUID 또는 SGID가 설정된 불필요한 대상이 존재함 (취약)" >> $Mk 2>&1
	echo "출력된 해당 대상은 2021 KISA 주요정보통신기반시설 기술적 취약점 분석평가 상세 가이드에서 불필요한 SUID,SGID 목록에 등재된 대상들입니다. 154p 참조" >> $Mk 2>&1
	chk 1
else
	echo "2021 KISA 주요정보통신기반시설 기술적 취약점 분석평가 상세 가이드에 등재된 '불필요한 SUID,SGID 목록'에 해당하는 대상이 존재하지 않습니다.154p 참조 (양호)" >> $Mk 2>&1
fi
rm -rf ./U13.txt
rm -rf ./U13_1.txt

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U14() {
rm -rf ./U14.txt
rm -rf ./U14_1.txt
rm -rf ./U14_2.txt
rm -rf ./U14a.txt
chk 0
echo "== [U-14]  사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정 ============="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>파일 및 디렉토리 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-14</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 홈 디렉터리 환경변수 파일 소유자가 root 또는, 해당 계정으로 지정되어 있고, 홈 디렉터리 환경변수 파일에 root와 소유자만 쓰기 권한이 부여된 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
echo "검사 대상:" >> $Mk 2>&1
cat /etc/passwd | grep -Ev "nologin|shutdown|halt|sync" | grep -v "#" | awk -F: '{print$1}' >> ./U14a.txt 2>&1
cat /etc/passwd | grep -Ev "nologin|shutdown|halt|sync" | grep -v "#" | awk -F: '{print$6}' >> ./U14.txt 2>&1
file_a=./U14a.txt
file_b=./U14.txt
while IFS= read -r line_a && IFS= read -r line_b <&3; do
	echo " 계정: $line_b , 홈디렉터리 : $line_a" >> $Mk 2>&1
done < "$file_b" 3< "$file_a" 
echo " ">> $Mk 2>&1

while read line1
	do
		echo "`ls -al $line1 | grep -E ".bashrc|.profile|.kshrc|.cshrc|.bash_profile|.login|.exrc|.netrc"`" >> ./U14_1.txt
done < ./U14.txt

while read line2
	do 
		echo $line2 | awk -F' ' '{print $1}' | cut -c 6 >> ./U14_2.txt
		echo $line2 | awk -F' ' '{print $1}' | cut -c 9 >> ./U14_2.txt

done < ./U14_1.txt

if [ `cat ./U14_2.txt | grep "w" | wc -l` -gt 0 ]; then chk 1
	cat ./U14_1.txt >> $Mk 2>&1
	echo "소유자 외 쓰기권한이 부여된 환경변수 파일이 존재함 (취약) " >> $Mk 2>&1
	echo " " >> $Mk 2>&1
else
	echo "소유자 외 쓰기권한이 부여된 환경변수 파일이 존재하지 않음 (양호)" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
fi


res=0
while IFS= read -r line_a && IFS= read -r line_b <&3; do
	if [ "`ls -al $line_a | grep -E ".bashrc|.profile|.kshrc|.cshrc|.bash_profile|.login|.exrc|.netrc" | awk -F' ' '{print $3}' | grep -wv "$line_b" | grep -v "root" | wc -l`" -gt 0 ]; then
		echo "[ $line_a 홈 디렉터리의 파일 ]" >> $Mk 2>&1
		echo "`ls -al $line_a | grep -E ".bashrc|.profile|.kshrc|.cshrc|.bash_profile|.login|.exrc|.netrc"`" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		echo "홈 디렉터리 환경변수 파일 소유자가 root, 또는 해당계정으로 지정되지 않음 (취약) " >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		res=+1
		chk 1	
	fi
done < "$file_b" 3< "$file_a"
if [ $res -eq 0 ]; then
	echo "홈 디렉터리 환경변수 파일 소유자가 root, 또는 해당계정으로 지정됨 (양호)" >> $Mk 2>&1
fi

rm -rf ./U14.txt
rm -rf ./U14_1.txt
rm -rf ./U14_2.txt
rm -rf ./U14a.txt

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U15() {
rm -rf ./U-15_world_writable.txt
chk 0
if [[ "$wwd" == "Y" || "$wwd" == "y" ]]; then
	echo "== [U-15]  world writable 파일 점검 ============================================"
else
	echo "== [U-15]  world writable 파일 점검 ==============[ N/A ]======================="
fi
echo "  <row>" >> $Mk 2>&1
echo "    <분류>파일 및 디렉토리 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>world writable 파일 점검</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-15</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 시스템 중요 파일에 world writable 파일이 존재하지 않거나, 존재 시 설정 이유를 확인하고 있는 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
if [[ "$wwd" == "Y" || "$wwd" == "y" ]]; then
	find / -type f -perm -2 -exec ls -l {} \; >> ./U-15_world_writable.txt 2>&1
	if [ `head -1 ./U-15_world_writable.txt | wc -l` -gt 0 ]; then chk 1
		echo "'U-15_world_writable.txt' 파일 참조" >> $Mk 2>&1
		echo "world writable 파일이 존재합니다. (취약)" >> $Mk 2>&1
		u15file=+1
	else
		echo "world writable 파일이 존재하지 않음 (양호)" >> $Mk 2>&1
	fi
else
	echo "전역변수 검사를 선택하지 않음 (N/A)" >> $Mk 2>&1
	chk 3
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U16() {
rm -rf ./U-16_list.txt
chk 0
echo "== [U-16]  /dev에 존재하지 않는 device 파일 점검 ==============================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>파일 및 디렉토리 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>/dev에 존재하지 않는 device 파일 점검</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-16</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : dev에 대한 파일 점검 후 존재하지 않은 device 파일을 제거한 경우 양호" >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

find /dev -type f -exec ls -l {} \; >> ./U-16_list.txt 2>&1
if [ `head -10 ./U-16_list.txt | wc -l` -gt 0 ]; then chk 1
	echo "`head -10 ./U-16_list.txt`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	echo "최대 10줄 까지 출력됨. 이하 'U-16_list.txt' 파일 참조" >> $Mk 2>&1
	echo "dev에 존재하지 않는 device 파일이 있습니다. (취약)" >> $Mk 2>&1
else
	echo " " >> $Mk 2>&1
	echo "검색 결과, dev에 존재하지 않는 device 파일이 없음 (양호)" >> $Mk 2>&1
	rm -rf ./U-16_list.txt
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}	

U17() {
aaa=0
chk 0
echo '== [U-17]  $HOME/.rhosts, hosts.equiv 사용 금지 ================================'
echo "  <row>" >> $Mk 2>&1
echo "    <분류>파일 및 디렉토리 관리</분류>" >> $Mk 2>&1
echo '    <점검항목>$HOME/.rhosts, hosts.equiv 사용 금지</점검항목>' >> $Mk 2>&1
echo "    <주통코드>U-17</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : login, shell, exec 서비스를 사용하지 않거나, 사용 시 아래와 같은 설정이 적용된 경우 양호. " >> $Mk 2>&1
echo '1. /etc/hosts.equiv 및 $HOME/.rhosts 파일 소유자가 root 또는, 해당 계정인 경우' >> $Mk 2>&1
echo '2. /etc/hosts.equiv 및 $HOME/.rhosts 파일 권한이 600 이하인 경우' >> $Mk 2>&1
echo '3. /etc/hosts.equiv 및 $HOME/.rhosts 파일 설정에 '+' 설정이 없는 경우' >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
res2=0
res=0
rm -rf ./U-17_hosts.equiv.txt
rm -rf ./U-17_rhosts.txt
if [ -e /etc/hosts.equiv ]; then
	echo "`ls -al /etc/hosts.equiv`" >> $Mk 2>&1
	if [ `ls -al /etc/hosts.equiv | awk -F' ' '{print $3}'` != "root" ]; then 
		echo "/etc/hosts.equiv 파일의 소유자가  root가 아님 (취약)" >> $Mk 2>&1
	fi
	

	if [ `stat -L -c '%a' /etc/hosts.equiv | cut -c 1` -gt 6 ]; then chk 1
		aaa=+1
	fi
	if [ `stat -L -c '%a' /etc/hosts.equiv | cut -c 2` -gt 0 ]; then chk 1
		aaa=+1
	fi
	if [ `stat -L -c '%a' /etc/hosts.equiv | cut -c 3` -gt 0 ]; then chk 1
		aaa=+1
	fi
	if [ $aaa != 0 ]; then 
		echo "부적절한 퍼미션 사용중. 600이하 권장 (취약)" >> $Mk 2>&1
	else
		echo "적절한 퍼미션 사용 (양호)" >> $Mk 2>&1
	fi


	if [ `cat /etc/hosts.equiv | grep "+" | wc -l` -gt 0 ]; then
		echo "[/etc/hosts.equiv 파일의 값]" >> ./U-17_hosts.equiv.txt
		cat /etc/hosts.equiv >> ./U-17_hosts.equiv.txt
		echo "/etc/hosts.equiv 파일에 '+' 값이 포함됨. 확인필요 (수동확인)  ☞ 'U-17_hosts.equiv.txt' 파일 참조" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		res2=+1 
	fi
	
else 
	echo "/etc/hosts.equiv 파일이 존재하지 않음 (양호)" >> $Mk 2>&1

fi
echo " " >> $Mk 2>&1
aaa=0
rm -rf ./U17a.txt
rm -rf ./U17b.txt
cat /etc/passwd | grep -Ev "nologin|shutdown|halt|sync" | grep -v "#" | awk -F: '{print $6}' >> ./U17b.txt 2>&1
cat /etc/passwd | grep -Ev "nologin|shutdown|halt|sync" | grep -v "#" | awk -F: '{print $1}' >> ./U17a.txt 2>&1
file_1=./U17a.txt
file_2=./U17b.txt
res=0
echo "검사 대상 : " >> $Mk 2>&1
while IFS= read -r line_a && IFS= read -r line_b <&3; do
	echo " 계정: $line_a , 홈디렉터리 : $line_b" >> $Mk 2>&1
done < "$file_1" 3< "$file_2" 
echo " ">> $Mk 2>&1

while IFS= read -r line_1 && IFS= read -r line_2 <&3; do
	if [ `ls -al $line_1 | grep ".rhosts" | wc -l` -gt 0 ]; then	
		if [ "`ls -al $line_1 | grep ".rhosts" | awk -F' ' '{print $3}' | grep -wv "$line_2" | grep -v "root" | wc -l`" -gt 0 ]; then
			echo "`ls -al $line_1/.rhosts`" >> $Mk 2>&1
			echo ".rhosts 파일 소유자가 root, 또는 해당계정으로 지정되지 않음 (취약) "  >> $Mk 2>&1
		fi

		if [ `stat -L -c '%a' $line_1/.rhosts | cut -c 1` -gt 6 ]; then chk 1
			aaa=+1
		fi
		if [ `stat -L -c '%a' $line_1/.rhosts | cut -c 2` -gt 0 ]; then chk 1
			aaa=+1
		fi
		if [ `stat -L -c '%a' $line_1/.rhosts | cut -c 3` -gt 0 ]; then chk 1
			aaa=+1
		fi
		if [ $aaa != 0 ]; then 
			echo "부적절한 퍼미션 사용중. 600이하 권장 (취약)" >> $Mk 2>&1
		else
			echo "적절한 퍼미션 사용 (양호)" >> $Mk 2>&1
		fi
		aaa=0
		if [ `cat $line_1/.rhosts | grep "+" | wc -l` -gt 0 ]; then
			echo "[$line_1/.rhosts 파일의 값]" >> ./U-17_rhosts.txt			
			cat $line_1/.rhosts >> ./U-17_rhosts.txt
			echo "========================================================================================" >> ./U-17_rhosts.txt
			echo " " >> ./U-17_rhosts.txt
			echo "$line_1/.rhosts 파일에 '+' 값이 포함됨 확인필요 (수동확인) ☞ 'U-17_rhosts.txt' 파일 참조" >> $Mk 2>&1
			echo " " >> $Mk 2>&1
			res2=+1
		fi
	else 
		echo "$line_1/.rhosts 파일이 존재하지 않음 (양호)" >> $Mk 2>&1
	
	fi
done < "$file_2" 3< "$file_1"

if [ $res2 != "0" ]; then
	chk 2
fi
rm -rf ./U17a.txt
rm -rf ./U17b.txt 
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}	

U18() {
chk 0
echo '== [U-18]  접속 IP 및 포트 제한 ================================================'
echo "  <row>" >> $Mk 2>&1
echo "    <분류>파일 및 디렉토리 관리</분류>" >> $Mk 2>&1
echo '    <점검항목>접속 IP 및 포트 제한</점검항목>' >> $Mk 2>&1
echo "    <주통코드>U-18</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 접속을 허용할 특정 호스트에 대한 IP 주소 및 포트 제한을 설정한 경우 양호 " >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
res=0
if [ `systemctl status iptables 2>/dev/null | grep "Active:" | awk -F: '{print$2}' | grep -w "active" | grep "running" |  wc -l` -gt 0 ]; then
	echo "[ Iptables가 동작중임 ]" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	echo "`systemctl status iptables | head -4`" >> $Mk 2>&1
else
	res=+1	
	echo "[ Iptables를 사용하지 않음 ]" >> $Mk 2>&1
fi

echo " " >> $Mk 2>&1

if [ `systemctl status firewalld 2>/dev/null | grep "Active:" | awk -F: '{print$2}' | grep -w "active" | grep "running" | wc -l` -gt 0 ]; then
	echo "[ Firewalld가 동작중임 ]" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	echo "`systemctl status firewalld | head -4`" >> $Mk 2>&1
else
	res=+1	
	echo "[ Firewalld를 사용하지 않음 ]" >> $Mk 2>&1
fi

if [ $res != "2" ]; then
	echo " " >> $Mk 2>&1
else
	echo "Iptables 또는 Firewalld를 사용하지 않음" >> $Mk 2>&1
fi
echo "해당 항목은 관리자와 인터뷰를 통해 접근통제를 시행중인지 아닌지 여부를 판단 (인터뷰)" >> $Mk 2>&1
chk 4
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U19() {
chk 0
echo '== [U-19]  Finger 서비스 비활성화 =============================================='
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo '    <점검항목>Finger 서비스 비활성화</점검항목>' >> $Mk 2>&1
echo "    <주통코드>U-19</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : Finger 서비스가 비활성화 되어 있는 경우 양호. " >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
if [ -e /etc/inetd.conf ]; then
	if [ `cat /etc/inetd.conf | grep "finger" | grep -v "#" | wc -l` -gt 0 ]; then
		echo "[ /etc/inetd.conf 설정 값 ]" >> $Mk 2>&1
		cat /etc/inetd.conf | grep "finger" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		echo "finger 설정이 사용됨 (취약)" >> $Mk 2>&1
		chk 1
	else
		echo "finger 설정이 사용되지 않음 (양호)" >> $Mk 2>&1
	fi
else
	echo "/etc/inetd.conf 파일이 존재하지 않음" >> $Mk 2>&1

fi

echo " " >> $Mk 2>&1
if [ -e /etc/xinetd.conf ]; then
	echo "[ /etc/xinetd.conf 설정 값 ]" >> $Mk 2>&1
	awk '/service finger/,/}/' /etc/xinetd.conf >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	if [ `awk '/service finger/,/}/' /etc/xinetd.conf |grep "disable" | awk -F' ' '{print$3}'` == "no" ]; then
		echo " " >> $Mk 2>&1
		echo "finger 설정이 사용됨 (취약)" >> $Mk 2>&1
		chk 1
	else
		echo "finger 설정이 사용되지 않음 (양호)" >> $Mk 2>&1
	fi
else
	echo "/etc/xinetd.conf 파일이 존재하지 않음" >> $Mk 2>&1
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}
U20() {
chk 0
echo '== [U-20]  Anonymous FTP 비활성화 =============================================='
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo '    <점검항목>Anonymous FTP 비활성화</점검항목>' >> $Mk 2>&1
echo "    <주통코드>U-20</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : Anonymous FTP (익명 FTP) 접속을 차단한 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
if [ `ps -ef | grep "ftp" | grep -v "grep" | wc -l` -gt 0 ];	then
	echo "[ FTP 서비스를 사용중 ] " >> $Mk 2>&1
	echo "`ps -ef | grep "ftp" | grep -v "grep"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	if [ -e /etc/vsftpd/vsftpd.conf ]; then
		echo "[ /etc/vsftpd/vsftpd.conf 설정값 ]" >> $Mk 2>&1
		echo "`cat /etc/vsftpd/vsftpd.conf | grep "anonymous_enable"`" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		if [ `cat /etc/vsftpd/vsftpd.conf | grep "anonymous_enable" | grep -v "#" | awk -F'=' '{print$2}'` != "NO" ]; then
			echo "anonymous_enable 설정이 허용됨 (취약)" >> $Mk 2>&1
			echo " " >> $Mk 2>&1
			chk 1
		else
			echo "anonymous_enable 설정이 제한됨 (양호)" >> $Mk 2>&1
			echo " " >> $Mk 2>&1		
		fi
	fi
	if [ `cat /etc/passwd | grep -w "ftp" | wc -l` -gt 0 ]; then
		echo "[ ftp 계정 ]" >> $Mk 2>&1		
		echo "`cat /etc/passwd | grep -w "ftp"`" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		echo "ftp 계정이 존재함. ('2021 주요정보통신기반시설 기술적 취약점 분석평가 가이드'에서는 해당 계정은 삭제하는 것을 권고) (취약)" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		chk 1
	fi
	if [ `cat /etc/passwd | grep -w "anonymous" | wc -l` -gt 0 ]; then
		echo "`cat /etc/passwd | grep -w "anonymous"`" >> $Mk 2>&1
		echo "anonymous 계정이 존재함. ('2021 주요정보통신기반시설 기술적 취약점 분석평가 가이드'에서는 해당 계정은 삭제하는 것을 권고) (취약)" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		chk 1
	fi	
else 
	echo "FTP 서비스를 사용하지 않음 (양호)" >> $Mk 2>&1
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U21() {
chk 0
res=0
echo '== [U-21]  r 계열 서비스 비활성화 =============================================='
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo '    <점검항목>r 계열 서비스 비활성화</점검항목>' >> $Mk 2>&1
echo "    <주통코드>U-21</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 불필요한 r 계열 서비스가 비활성화 되어 있는 경우 양호." >> $Mk 2>&1
echo "※ r-command: 인증 없이 관리자의 원격접속을 가능하게 하는 명령어들 (rsh,rlogin,rexec 등)" >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
if [ -e /etc/inetd.conf ]; then
	if [ `cat /etc/inetd.conf | grep -w "rlogin" | grep -v "#"` -gt 0 ]; then
		echo "`cat /etc/inetd.conf | grep -w "rlogin"`" >> $Mk 2>&1
		echo "/etc/inetd.conf 파일에 rlogin 설정이 존재함 " >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		res=+1
	fi
	if [ `cat /etc/inetd.conf | grep -w "rsh" | grep -v "#"` -gt 0 ]; then
		echo "`cat /etc/inetd.conf | grep -w "rsh"`" >> $Mk 2>&1
		echo "/etc/inetd.conf 파일에 rsh 설정이 존재함 " >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		res=+1
	fi
	if [ `cat /etc/inetd.conf | grep -w "rexec" | grep -v "#"` -gt 0 ]; then
		echo "`cat /etc/inetd.conf | grep -w "rexec"`" >> $Mk 2>&1
		echo "/etc/inetd.conf 파일에 rlogin 설정이 존재함 " >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		res=+1
	fi
	if [ $res -gt 0 ]; then
		echo "관리자와 인터뷰를 통해 해당 r계열 서비스가 사용되지 않거나 불필요할 경우 취약 (인터뷰)" >> $Mk 2>&1
		chk 4
	fi
else
	echo "/etc/inetd.conf 파일이 존재하지 않음." >> $Mk 2>&1
fi
if [ -d /etc/xinetd.d/ ]; then
	if [ `ls -al /etc/xinetd.d/ | egrep "rsh|rlogin|rexec" | egrep -v "grep|klogin|kshell|kexec" | wc -l` -gt 0 ]; then
		echo "[ r계열 서비스 설정파일이 존재함 ]" >> $Mk 2>&1
		echo "`ls -al /etc/xinetd.d/* | egrep "rsh|rlogin|rexec" | egrep -v "grep|klogin|kshell|kexec"`" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		echo "관리자와 인터뷰를 통해 해당 r계열 서비스가 사용되지 않거나 불필요할 경우 취약 (인터뷰)" >> $Mk 2>&1
		chk 4
		
	else
		echo " r계열 서비스(rsh, rlogin, rexec) 설정이 존재하지 않음 (양호)"  >> $Mk 2>&1
	fi 
else
	echo "/etc/xinetd.d/ 디렉터리가 존재하지 않음." >> $Mk 2>&1
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U22() {
chk 0
echo "== [U-22]  crond 파일 소유자 및 권한 설정 ======================================"
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo '    <점검항목>crond 파일 소유자 및 권한 설정</점검항목>' >> $Mk 2>&1
echo "    <주통코드>U-22</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : crontab 명령어 일반사용자 금지 및 cron 관련 파일이 640 이하인 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
filename1="/etc/crontab /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* /etc/cron.allow /etc/cron.deny /var/spool/cron/* /etc/cron.d/*"
if [ `ls -al /usr/bin/crontab |awk -F' ' '{print$1}' | grep "s" | wc -l` -gt 0 ]; then
	echo "`ls -al /usr/bin/crontab`" >> $Mk 2>&1
	echo "/usr/bin/crontab 에 setUID가 설정됨. 750 권장 (취약)" >> $Mk 2>&1
	chk 1
fi

for aa in $filename1
do
	if [ -e $aa ]; then
		if [ `ls -al $aa | awk -F' ' '{print$3}' | grep -v "root" | wc -l` -gt 0 ]; then
			echo "`ls -al $aa`의 소유자가 root가 아님 (취약)" >> $Mk 2>&1
			chk 1		
		fi
	fi
done	
echo " " >> $Mk 2>&1

res=0
for bb in $filename1
do
	if [ -e $bb ]; then
		if [ `stat -L -c '%a' $bb | cut -c 1` -gt 6 ]; then
			res=+1	
		fi
		if [ `stat -L -c '%a' $bb | cut -c 2` -gt 4 ]; then
			res=+1
		fi			
 		if [ `stat -L -c '%a' $bb | cut -c 3` -gt 0 ]; then
			res=+1	
		fi
		if [ $res -gt 0 ]; then
			echo "`ls -al $bb` 의 권한이 부적절함. 640이하 권장 (취약)"  >> $Mk 2>&1
			chk 1		
		fi
		res=0
	fi
done		
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}


U23() {
chk 0
echo '== [U-23]  DoS 공격에 취약한 서비스 비활성화 ==================================='
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo '    <점검항목>DoS 공격에 취약한 서비스 비활성화</점검항목>' >> $Mk 2>&1
echo "    <주통코드>U-23</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 사용하지 않는 DoS 공격에 취약한 서비스가 비활성화 된 경우 양호." >> $Mk 2>&1
echo "검사항목 : echo, discard, daytime, chargen" >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1


if [ -e /etc/xinetd.d/echo-stream ]; then
	if [ `awk '/service echo/,/}/' /etc/xinetd.d/echo-stream | grep "disable" | grep -v "#" | awk -F= '{print$2}' | grep "yes" | wc -l` -gt 0 ]; then
		echo "echo-stream 설정 양호" >> $Mk 2>&1
	else
		echo "echo-stream 설정 취약"  >> $Mk 2>&1
		echo "`awk '/service echo/,/}/' /etc/xinetd.d/echo-stream | grep -v "#" | grep -v '^$'`" >> $Mk 2>&1
 		echo "disable 설정이 no 또는 주석처리됨. (#주석처리된 경우, disable 설정 값이 출력되지않음)(취약)" >> $Mk 2>&1
		chk 1
	fi
else 
	echo "/etc/xinetd.d/echo-stream 파일이 존재하지 않음" >> $Mk 2>&1
fi

if [ -e /etc/xinetd.d/echo-dgram ]; then
	if [ `awk '/service echo/,/}/' /etc/xinetd.d/echo-dgram | grep "disable" | grep -v "#" | awk -F= '{print$2}' | grep "yes" | wc -l` -gt 0 ]; then
		echo "echo-dgram 설정 양호" >> $Mk 2>&1
	else 
		echo "echo-dgram 설정 취약"  >> $Mk 2>&1
		echo "`awk '/service echo/,/}/' /etc/xinetd.d/echo-dgram | grep -v "#" | grep -v '^$'`" >> $Mk 2>&1
 		echo "disable 설정이 no 또는 주석처리됨. (#주석처리된 경우, disable 설정 값이 출력되지않음)(취약)" >> $Mk 2>&1
		chk 1
	fi
else 
	echo "/etc/xinetd.d/echo-dgram 파일이 존재하지 않음" >> $Mk 2>&1
fi

if [ -e /etc/xinetd.d/daytime-dgram ]; then
	if [ `awk '/service daytime/,/}/' /etc/xinetd.d/daytime-dgram | grep "disable" | grep -v "#" | awk -F= '{print$2}' | grep "yes" | wc -l` -gt 0 ]; then
		echo "daytime-dgram 설정 양호" >> $Mk 2>&1
	else
		echo "daytime-dgram 설정 취약"  >> $Mk 2>&1 
		echo "`awk '/service daytime/,/}/' /etc/xinetd.d/daytime-dgram | grep -v "#" | grep -v '^$'`" >> $Mk 2>&1
 		echo "disable 설정이 no 또는 주석처리됨. (#주석처리된 경우, disable 설정 값이 출력되지않음)(취약)" >> $Mk 2>&1
		chk 1
	fi
else 
	echo "/etc/xinetd.d/daytime-dgram 파일이 존재하지 않음" >> $Mk 2>&1	
fi

if [ -e /etc/xinetd.d/daytime-stream ]; then
	if [ `awk '/service daytime/,/}/' /etc/xinetd.d/daytime-stream | grep "disable" | grep -v "#" | awk -F= '{print$2}' | grep "yes" | wc -l` -gt 0 ]; then
		echo "daytime-stream 설정 양호" >> $Mk 2>&1
	else 
		echo "daytime-stream 설정 취약"  >> $Mk 2>&1 		
		echo "`awk '/service daytime/,/}/' /etc/xinetd.d/daytime-stream | grep -v "#" | grep -v '^$'`" >> $Mk 2>&1
 		echo "disable 설정이 no 또는 주석처리됨. (#주석처리된 경우, disable 설정 값이 출력되지않음)(취약)" >> $Mk 2>&1
		chk 1
	fi
else 
	echo "/etc/xinetd.d/daytime-stream 파일이 존재하지 않음" >> $Mk 2>&1
fi

if [ -e /etc/xinetd.d/chargen-dgram ]; then
	if [ `awk '/service chargen/,/}/' /etc/xinetd.d/chargen-dgram | grep "disable" | grep -v "#" | awk -F= '{print$2}' | grep "yes" | wc -l` -gt 0 ]; then
		echo "chargen-dgram 설정 양호"  >> $Mk 2>&1
	else
		echo "chargen-dgram 설정 취약"  >> $Mk 2>&1
		echo "`awk '/service chargen/,/}/' /etc/xinetd.d/chargen-dgram | grep -v "#" | grep -v '^$'`" >> $Mk 2>&1
 		echo "disable 설정이 no 또는 주석처리됨. (#주석처리된 경우, disable 설정 값이 출력되지않음)(취약)" >> $Mk 2>&1  
		chk 1
	fi
else 
	echo "/etc/xinetd.d/chargen-dgram 파일이 존재하지 않음" >> $Mk 2>&1
fi

if [ -e /etc/xinetd.d/chargen-stream ]; then
	if [ `awk '/service chargen/,/}/' /etc/xinetd.d/chargen-stream | grep "disable" | grep -v "#" | awk -F= '{print$2}' | grep "yes" | wc -l` -gt 0 ]; then
		echo "chargen-stream 설정 양호" >> $Mk 2>&1
	else
		echo "chargen-stream 설정 취약" >> $Mk 2>&1  
		echo "`awk '/service chargen/,/}/' /etc/xinetd.d/chargen-stream | grep -v "#" | grep -v '^$'`" >> $Mk 2>&1
 		echo "disable 설정이 no 또는 주석처리됨. (#주석처리된 경우, disable 설정 값이 출력되지않음)(취약)" >> $Mk 2>&1
		chk 1
	fi
else 
	echo "/etc/xinetd.d/chargen-stream 파일이 존재하지 않음" >> $Mk 2>&1
fi

if [ -e /etc/xinetd.d/discard-dgram ]; then
	if [ `awk '/service discard/,/}/' /etc/xinetd.d/discard-dgram | grep "disable" | grep -v "#" | awk -F= '{print$2}' | grep "yes" | wc -l` -gt 0 ]; then
		echo "discard-dgram 설정 양호" >> $Mk 2>&1
	else 
		echo "discard-dgram 설정 취약" >> $Mk 2>&1
		echo "`awk '/service discard/,/}/' /etc/xinetd.d/discard-dgram | grep -v "#" | grep -v '^$'`" >> $Mk 2>&1
 		echo "disable 설정이 no 또는 주석처리됨. (#주석처리된 경우, disable 설정 값이 출력되지않음)(취약)" >> $Mk 2>&1
		chk 1
	fi
else 
	echo "/etc/xinetd.d/discard-dgram 파일이 존재하지 않음" >> $Mk 2>&1
fi

if [ -e /etc/xinetd.d/discard-stream ]; then
	if [ `awk '/service discard/,/}/' /etc/xinetd.d/discard-stream | grep "disable" | grep -v "#" | awk -F= '{print$2}' | grep "yes" | wc -l` -gt 0 ]; then
		echo "discard-stream 설정 양호" >> $Mk 2>&1
	else 
		echo "discard-stream 설정 취약" >> $Mk 2>&1
		echo "`awk '/service discard/,/}/' /etc/xinetd.d/discard-stream | grep -v "#" | grep -v '^$'`" >> $Mk 2>&1
 		echo "disable 설정이 no 또는 주석처리됨. (#주석처리된 경우, disable 설정 값이 출력되지않음)(취약)" >> $Mk 2>&1
		chk 1
	fi
else 
	echo "/etc/xinetd.d/discard-stream 파일이 존재하지 않음" >> $Mk 2>&1
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U24(){
chk 0
echo '== [U-24]  NFS 서비스 비활성화  ================================================'
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo '    <점검항목>NFS 서비스 비활성화 </점검항목>' >> $Mk 2>&1
echo "    <주통코드>U-24</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 불필요한 NFS 서비스 관련 데몬이 비활성화 되어있는 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

if [ `ps -ef | egrep "nfs|statd|lockd" | grep -v "grep" | grep -v "kblockd" | wc -l` -gt 0 ]; then
	echo "[ 프로세스 현황 ]" >> $Mk 2>&1
	echo "`ps -ef | egrep "nfs|statd|lockd" | grep -v "grep" | grep -v "kblockd"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	echo "NFS 서비스가 활성화 됨. 관리자와 인터뷰 확인필요. (인터뷰)" >> $Mk 2>&1
	chk 4
else
	echo "NFS 서비스를 사용하지 않음. (양호)" >> $Mk 2>&1
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}


U25() {
chk 0
echo '== [U-25]  NFS 접근 통제  ======================================================'
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo '    <점검항목>NFS 접근 통제 </점검항목>' >> $Mk 2>&1
echo "    <주통코드>U-25</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 불필요한 NFS 서비스를 사용하지 않거나, 불가피하게 사용 시 everyone 공유를 제거한 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

if [ `ps -ef | egrep "nfs|statd|lockd" | grep -v "grep" | grep -v "kblockd" | wc -l` -gt 0 ]; then
	echo "[ 프로세스 현황 ]" >> $Mk 2>&1
	echo "`ps -ef | egrep "nfs|statd|lockd" | grep -v "grep" | grep -v "kblockd"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	echo "NFS 서비스가 활성화 됨." >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	if [ -e /etc/exports ]; then
		echo "[ /etc/exports 설정 값 ]" >> $Mk 2>&1
		echo "`cat /etc/exports`" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		if [ `cat /etc/exports | egrep "insecure|root_squash" | grep -v "no_root" | wc -l` -gt 0 ]; then
			echo "insecure 또는 root_squash 구문이 설정됨. (취약)" >> $Mk 2>&1
			chk 1
		else 
			echo "insecure 또는 root_squash 설정이 존재하지 않음. (양호)" >> $Mk 2>&1
		fi
	else
		echo "/etc/exports 파일이 존재하지 않음" >> $Mk 2>&1
	fi
else
	echo "NFS 서비스를 사용하지 않음. (양호)" >> $Mk 2>&1
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}


U26() {
chk 0
echo '== [U-26]  automountd 제거 ====================================================='
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo '    <점검항목>automountd 제거</점검항목>' >> $Mk 2>&1
echo "    <주통코드>U-26</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : automountd 서비스가 비활성화 되어있는 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
if [ `ps -ef | egrep "automount|autofs" | grep -v "grep" | wc -l` -gt 0 ]; then
	echo "[ 프로세스 현황 ]" >> $Mk 2>&1
	echo "`ps -ef | egrep "automount|autofs" | grep -v "grep"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	echo "automountd 서비스가 활성화 되어있음. (취약)" >> $Mk 2>&1
	chk 1
else
	echo "automountd 서비스가 비활성화 되어있음. (양호)" >> $Mk 2>&1
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U27() {
chk 0
echo '== [U-27]  RPC 서비스 확인 ====================================================='
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo '    <점검항목>RPC 서비스 확인</점검항목>' >> $Mk 2>&1
echo "    <주통코드>U-27</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 불필요한 RPC 서비스가 비활성화 되어있는 경우 양호." >> $Mk 2>&1
echo "검사항목 : rpc.cmsd,rpc.ttdbserverd,sadmind,rusersd,walld,sprayd,rstatd,rpc.nisd,rexd,rpc.pcnfsd,rpc.statd,rpc.ypupdated,rpc.rquotad,kcms_server,cachefsd" >> $Mk 2>&1
echo "불필요한 RPC 서비스 목록 - 156p 참조" >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

list1="rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rexd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd"

if [ -d /etc/xinetd.d/ ]; then
	echo "[ /etc/xinetd.d/ 디렉터리가 존재함 ]" >> $Mk 2>&1
	if [ `ls -al /etc/xinetd.d/ | egrep $list1 | grep -v "grep" | wc -l` -gt 0 ]; then
		echo "`ls -al /etc/xinetd.d/ | egrep $list1 | grep -v "grep"`" >> $Mk 2>&1
		echo "불필요한 RPC 서비스가 존재함. (취약)" >> $Mk 2>&1
		chk 1
	else
		echo "불필요한 RPC 서비스가 존재하지 않음. (양호)" >> $Mk 2>&1
	fi
else
	echo "[ /etc/xinetd.d/ 디렉터리가 존재하지않음 ]" >> $Mk 2>&1
fi
echo " " >> $Mk 2>&1
if [ -d /etc/inetd.d/ ]; then
	echo "[ /etc/inetd.d/ 디렉터리가 존재함 ]" >> $Mk 2>&1
	if [ `ls -al /etc/inetd.d/ | egrep $list1 | grep -v "grep" | wc -l` -gt 0 ]; then
		echo "`ls -al /etc/inetd.d/* | egrep $list1 | grep -v "grep"`" >> $Mk 2>&1
		echo "불필요한 RPC 서비스가 존재함. (취약)" >> $Mk 2>&1
		chk 1
	else
		echo "불필요한 RPC 서비스가 존재하지 않음. (양호)" >> $Mk 2>&1
	fi
else
	echo "[ /etc/inetd.d/ 디렉터리가 존재하지않음 ]" >> $Mk 2>&1
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U28() {
chk 0
echo '== [U-28]  NIS, NIS+ 점검 ======================================================'
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo '    <점검항목>NIS, NIS+ 점검</점검항목>' >> $Mk 2>&1
echo "    <주통코드>U-28</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : NIS 서비스가 비활성화 되어있거나, 필요 시 NIS+를 사용하는 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

if [ `ps -ef | egrep "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated" | grep -v "grep" | wc -l` -gt 0 ]; then
	echo "[ 프로세스 현황 ]" >> $Mk 2>&1
	echo "`ps -ef | egrep "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated" | grep -v "grep"`"  >> $Mk 2>&1
	echo "NIS 서비스가 활성화 되어있음. (취약)"  >> $Mk 2>&1
	chk 1
else
	echo "NIS 서비스가 비활성화 되어있음. (양호)"  >> $Mk 2>&1
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U29() {
chk 0
echo '== [U-29]  tftp, talk 서비스 비활성화 =========================================='
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo '    <점검항목>tftp, talk 서비스 비활성화</점검항목>' >> $Mk 2>&1
echo "    <주통코드>U-29</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : tftp, talk, ntalk 서비스가 비활성화 되어있는 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

if [ -e /etc/xinetd.d/ ]; then
	echo "[ /etc/xinetd.d/ 디렉터리가 존재함 ]" >> $Mk 2>&1
	if [ `ls -al /etc/xinetd.d/ | egrep "tftp|talk|ntalk" | wc -l` -gt 0 ]; then
		echo "`ls -al /etc/xinetd.d/ | egrep "tftp|talk|ntalk"`" >> $Mk 2>&1
		echo "tftp 또는 talk, ntalk 서비스가 존재함. (취약)" >> $Mk 2>&1
		chk 1
	else
		echo "tftp 또는 talk, ntalk 서비스가 존재하지 않음. (양호)" >> $Mk 2>&1
	fi
else
	echo "[ /etc/xinetd.d/ 디렉터리가 존재하지 않음 ]" >> $Mk 2>&1
fi
echo " " >> $Mk 2>&1

if [ -e /etc/inetd.conf ]; then
	echo "[ /etc/inetd.conf 파일이 존재함 ]" >> $Mk 2>&1
	if [ `cat /etc/inetd.conf | egrep "tftp|talk|ntalk" | grep -v "#" | wc -l` -gt 0 ]; then
		echo "`cat /etc/inetd.conf | egrep "tftp|talk|ntalk" | grep -v "#"`" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		echo "tftp 또는 talk, ntalk 서비스가 존재함. (취약)"  >> $Mk 2>&1
		chk 1
	else
		echo "tftp 또는 talk, ntalk 서비스가 존재하지 않음. (양호)" >> $Mk 2>&1
	fi
else
	echo "[ /etc/inetd.conf 파일이 존재하지 않음 ]" >> $Mk 2>&1
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U30() {
chk 0
echo '== [U-30]  Sendmail 버전 점검 =================================================='
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo '    <점검항목>Sendmail 버전 점검</점검항목>' >> $Mk 2>&1
echo "    <주통코드>U-30</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : Sendmail 버전이 최신버전인 경우 양호." >> $Mk 2>&1
echo "sendmail 8.18.1 - 2024-01-31" >> $Mk 2>&1
echo "sendmail 8.17.2 - 2023-06-03" >> $Mk 2>&1
echo "sendmail 8.17.1 - 2021-08-17" >> $Mk 2>&1
echo "참고 - https://ftp.sendmail.org" >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

if [ `ps -ef | grep "sendmail" | grep -v "grep" | wc -l` -gt 0 ]; then
	echo "[ Sendmail 서비스가 활성화 됨 ]" >> $Mk 2>&1
	echo "`ps -ef | grep "sendmail" | grep -v "grep"`" >> $Mk 2>&1
	echo " ">> $Mk 2>&1
	if [ `sendmail -d0.1 < /dev/null | grep -i Version | awk -F. '{print$2}'` -le 17 ]; then
		echo "현재 사용중인 버전 :"	 >> $Mk 2>&1	
		echo "`sendmail -d0.1 < /dev/null | grep -i "Version"`" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		echo "해당 버전은 최신버전이 아닙니다. (취약)" >> $Mk 2>&1
		echo "2024년 2월 기준 최신버전 - 8.18.1  " >> $Mk 2>&1
		chk 1
	else
		echo "[ 현재 사용중인 버전 ]" >> $Mk 2>&1		
		echo "`sendmail -d0.1 < /dev/null | grep -i "Version"`" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		echo "Sendmail 최신버전 사용중 (양호)"  >> $Mk 2>&1
		echo "2024년 2월 기준 최신버전 - 8.18.1  " >> $Mk 2>&1

	fi
else
	echo "Sendmail 서비스가 비활성화 됨 (양호)" >> $Mk 2>&1
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}	

U31() {
chk 0
echo '== [U-31]  스팸 메일 릴레이 제한 ==============================================='
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo '    <점검항목>스팸 메일 릴레이 제한</점검항목>' >> $Mk 2>&1
echo "    <주통코드>U-31</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : SMTP 서비스를 사용하지 않거나 릴레이 제한이 설정되어 있는 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

if [ `ps -ef | grep "sendmail" | grep -v "grep" | wc -l` -gt 0 ]; then
	echo "[ Sendmail 서비스가 활성화 됨 ]" >> $Mk 2>&1
	echo "`ps -ef | grep "sendmail" | grep -v "grep"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	if [ -e /etc/mail/sendmail.cf ]; then
		echo "[ /etc/mail/sendmail.cf 설정 ]" >> $Mk 2>&1
		echo "`cat /etc/mail/sendmail.cf | grep "R$\*" | grep "Relaying denied"`" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		if [ `cat /etc/mail/sendmail.cf | grep "R$\*" | grep "Relaying denied" | grep -v "#R" | wc -l` -gt 0 ]; then
			echo "Relaying denied 설정이 되어있음. (양호)" >> $Mk 2>&1
		else
			chk 1
			echo "Relaying denied 가 주석처리 되어있거나 설정되지 않음. (취약)" >> $Mk 2>&1
		fi
 	else
		echo "/etc/mail/sendmail.cf 파일이 존재하지않음." >> $Mk 2>&1
	fi
else
	echo "SMTP 서비스가 활성화 되지않음. (양호)" >> $Mk 2>&1
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}	

U32() {
chk 0
echo '== [U-32]  일반사용자의 Sendmail 실행 방지 ====================================='
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo '    <점검항목>일반사용자의 Sendmail 실행 방지</점검항목>' >> $Mk 2>&1
echo "    <주통코드>U-32</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : SMTP 서비스 미사용 또는, 일반 사용자의 Sendmail 실행 방지가 설정된 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

if [ `ps -ef | grep "sendmail" | grep -v "grep" | wc -l` -gt 0 ]; then
	echo "[ Sendmail 서비스가 활성화 됨 ]" >> $Mk 2>&1
	echo "`ps -ef | grep "sendmail" | grep -v "grep"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	if [ -e /etc/mail/sendmail.cf ]; then
		echo "[ /etc/mail/sendmail.cf 설정 값 ]" >> $Mk 2>&1
		echo "`cat /etc/mail/sendmail.cf | grep "PrivacyOptions" | grep "restrictqrun"`" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		if [ `cat /etc/mail/sendmail.cf | grep "PrivacyOptions" | grep "restrictqrun" | wc -l` -gt 0 ]; then
			echo "restrictqrun 설정이 되어있음. (양호)" >> $Mk 2>&1
		else
			chk 1
			echo "restrictqrun 가 주석처리 되어있거나 설정되지 않음. (취약)" >> $Mk 2>&1
		fi
 	else
		echo "/etc/mail/sendmail.cf 파일이 존재하지않음." >> $Mk 2>&1
	fi
else
	echo "SMTP 서비스가 활성화 되지않음. (양호)" >> $Mk 2>&1
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}	

U33() {
chk 0
echo '== [U-33]  DNS 보안 버전 패치 =================================================='
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo '    <점검항목>DNS 보안 버전 패치</점검항목>' >> $Mk 2>&1
echo "    <주통코드>U-33</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : DNS 서비스를 사용하지 않거나, 주기적으로 패치를 관리하고 있는 경우 양호." >> $Mk 2>&1
echo "BIND DNS 9.19.19 - 2023-12-20" >> $Mk 2>&1
echo "BIND DNS 9.19.18 - 2023-11-15" >> $Mk 2>&1
echo "BIND DNS 9.19.17 - 2023-09-20" >> $Mk 2>&1
echo "최신버전 참조 - https://ftp.isc.org/isc/bind9/ 또는  http://www.isc.org/downloads/" >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
if [ `ps -ef | grep "named" | grep -v "grep" | wc -l` -gt 0 ]; then
	echo "[ DNS 서비스 사용중 ]" >> $Mk 2>&1
	echo "`ps -ef | grep "named" | grep -v "grep"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	echo "[ BIND DNS 버전 ]" >> $Mk 2>&1
	echo "`named -v | sed 's/[<>]//g'`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	if [ `named -v | awk -F. '{print$2}'` -le 18 ]; then
		echo "BIND DNS 최신버전이 아님. (취약)" >> $Mk 2>&1
		echo "2024년 2월 기준 최신버전 - 9.19.19" >> $Mk 2>&1	
		chk 1
	else
		echo "BIND DNS 최신버전 사용중. (양호)"  >> $Mk 2>&1
	fi
else
	echo "DNS 서비스를 사용하지 않음. (양호)" >> $Mk 2>&1

fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}	

U34() {
chk 0
echo '== [U-34]  DNS Zone Transfer 설정 =============================================='
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo '    <점검항목>DNS Zone Transfer 설정</점검항목>' >> $Mk 2>&1
echo "    <주통코드>U-34</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : DNS 서비스 미사용 또는, Zone Transfer를 허가된 사용자에게만 허용한 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

if [ `ps -ef | grep "named" | grep -v "grep" | wc -l` -gt 0 ]; then
	echo "[ DNS 서비스 사용중 ]" >> $Mk 2>&1
	echo "`ps -ef | grep "named" | grep -v "grep"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	if [ -e /etc/named.conf ]; then
		echo "[ /etc/named.conf 설정 값 ]" >> $Mk 2>&1
		echo "`cat /etc/named.conf | grep -v "//" | sed ':a;N;$!ba;s:/\*.*\*/::g'`" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		if [ `cat /etc/named.conf | grep "allow-transfer" | wc -l` -gt 0 ]; then
			echo "allow-transfer 설정이 존재함. (양호)" >> $Mk 2>&1
		else 
			echo "allow-transfer 설정이 존재하지 않음. (취약)" >> $Mk 2>&1
			chk 1
		fi
	else 
		echo "/etc/named.conf 파일이 존재하지 않음." >> $Mk 2>&1
	fi
	if [ -e /etc/named.boot ] ; then
		echo "[ /etc/named.boot 설정 값 ]" >> $Mk 2>&1
		echo "`cat /etc/named.boot | grep -v "//" | sed ':a;N;$!ba;s:/\*.*\*/::g'`" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		if [ `cat /etc/named.boot | grep "xfrnets" | wc -l` -gt 0 ]; then
			echo "xfrnets 설정이 존재함. (양호)" >> $Mk 2>&1
		else
			echo "xfrnets 설정이 존재하지 않음. (취약)" >> $Mk 2>&1
			chk 1
		fi
	else
		echo "/etc/named.boot 파일이 존재하지 않음" >> $Mk 2>&1
	fi
else
	echo "DNS 서비스를 사용하지 않음. (양호)" >> $Mk 2>&1
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U42() {
chk 0
echo '== [U-42]  최신 보안패치 및 벤더 권고사항 적용 ================================='
echo "  <row>" >> $Mk 2>&1
echo "    <분류>패치 관리</분류>" >> $Mk 2>&1
echo '    <점검항목>최신 보안패치 및 벤더 권고사항 적용</점검항목>' >> $Mk 2>&1
echo "    <주통코드>U-42</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 패치 적용 정책을 수립하여 주기적으로 패치관리를 하고 있으며, 패치 관련 내용을 확인하고 적용했을 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
echo "[ OS 정보  ]" >> $Mk 2>&1
echo "`cat /etc/*-release |grep -v "ANSI" |grep -v "URL" | head -3`" >> $Mk 2>&1
echo " " >> $Mk 2>&1
if [ `cat /etc/*-release | grep '^VERSION_ID' | head -1 | awk -F'"' '{print$2}'` -eq 7 ]; then
	echo "지원이 종료되지 않은 CentOS 를 사용중. (양호)" >> $Mk 2>&1
else
	echo "지원이 종료된 CentOS를 사용중. (취약)" >> $Mk 2>&1
	chk 1
fi
echo " " >> $Mk 2>&1
echo "참고 - " >> $Mk 2>&1
echo "CentOS 6 - 2020.11 지원종료" >> $Mk 2>&1
echo "CentOS 7 - 2024.06 지원종료" >> $Mk 2>&1
echo "CentOS 8 - 2021.12 지원종료" >> $Mk 2>&1
echo "https://endoflife.software/operating-systems/linux/centos" >> $Mk 2>&1

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U43() {
chk 0
echo '== [U-43]  로그의 정기적 검토 및 보고 =========================================='
echo "  <row>" >> $Mk 2>&1
echo "    <분류>로그 관리</분류>" >> $Mk 2>&1
echo '    <점검항목>로그의 정기적 검토 및 보고</점검항목>' >> $Mk 2>&1
echo "    <주통코드>U-43</주통코드>" >> $Mk 2>&1
echo "    <위험도>상</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 접속기록 등의 보안 로그, 응용 프로그램 및 시스템 로그 기록에 대해 정기적으로 검토, 분석, 리포트 작성 및 보고 등의 조치가 이루어지는 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
if [ `w | head -5 | wc -l` -gt 1 ]; then
	echo "[ utmp 사용중 ] (양호)" >> $Mk 2>&1
else
	echo "[ utmp 미사용 ] (취약)">> $Mk 2>&1
	chk 1	
fi
echo " " >> $Mk 2>&1
if [ `last | head -5 | wc -l` -gt 1 ]; then
	echo "[ wtmp 사용중 ] (양호)" >> $Mk 2>&1
else
	echo "[ wtmp 미사용 ] (취약)" >> $Mk 2>&1
	chk 1
fi
echo " " >> $Mk 2>&1
if [ `lastb | head -5 | wc -l` -gt 1 ]; then
	echo "[ btmp 사용중 ] (양호)" >> $Mk 2>&1
else
	echo "[ btmp 미사용 ] (취약)" >> $Mk 2>&1
	chk 1
fi
echo " " >> $Mk 2>&1
if [ -e /var/log/sulog ]; then
	echo " [ sulog 사용중 ] (양호)" >> $Mk 2>&1
else
	echo " /var/log/sulog 파일이 존재하지 않음"  >> $Mk 2>&1
	echo " [ sulog 를 찾을 수 없음 ] (취약)" >> $Mk 2>&1
	chk 1
fi
echo " " >> $Mk 2>&1

if [ `ps -ef | grep "vsftpd" | grep -v "grep" | wc -l` -gt 0 ]; then
	echo " [ FTP 서비스 사용중 ]" >> $Mk 2>&1
	if [ -e /etc/vsftpd/vsftpd.conf ]; then
		echo "/etc/vsftpd/vsftpd.conf 설정 값" >> $Mk 2>&1
		echo "`cat /etc/vsftpd/vsftpd.conf | grep "xferlog"`" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		if [ `cat /etc/vsftpd/vsftpd.conf | grep "xferlog_enable" | grep -v "#" | awk -F= '{print$2}'` == "YES" ]; then
			echo "[ xferlog_enalbe 설정됨 ] (양호)" >> $Mk 2>&1			
			if [ `cat /etc/vsftpd/vsftpd.conf | grep "xferlog_file" | grep -v "#" | wc -l` -gt 0 ]; then
				echo "[ xferlog_file 설정됨 ] (양호)" >> $Mk 2>&1
			else
				echo "[ xferlog_file 설정이 주석처리 되거나 존재하지 않음 ] (취약)" >> $Mk 2>&1
				chk 1
			fi
		else
			echo "[ xferlog_enalbe 설정되지 않음 ] (취약)" >> $Mk 2>&1
			chk 1
		fi
	else
		echo "/etc/vsftpd/vsftpd.conf 파일이 존재하지 않음" >> $Mk 2>&1
	fi
else
	echo " [FTP 서비스 미사용 ]" >> $Mk 2>&1

fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U44() {
chk 0
echo "== [U-44]  root 이외의 UID가 '0' 금지 =========================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>계정관리</분류>" >> $Mk 2>&1
echo "    <점검항목>root 이외의 UID가 '0' 금지</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-44</주통코드>" >> $Mk 2>&1
echo "    <위험도>중</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : root 계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

if [ `cat /etc/passwd | grep -v "root" | awk -F: '{print$3}' | grep -w "0" | wc -l` -gt 0 ]; then
	echo "`cat /etc/passwd | grep -v "root" | awk -F: '{print$3}' | grep -w "0"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	echo "root 이외 UID가 '0'인 계정이 존재함. (취약)" >> $Mk 2>&1
else
	echo "root 이외 UID가 '0'인 계정이 존재하지 않음. (양호)" >> $Mk 2>&1
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U45() {
chk 0
echo "== [U-45]  root 계정 su 제한 ==================================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>계정관리</분류>" >> $Mk 2>&1
echo "    <점검항목>root 계정 su 제한</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-45</주통코드>" >> $Mk 2>&1
echo "    <위험도>하</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : su 명령어를 특정 그룹에 속한 사용자만 사용하도록 제한되어 있는 경우 양호. " >> $Mk 2>&1
echo "* 일반사용자 계정 없이 root 계정만 사용하는 경우 su 명령어 사용제한 불필요 " >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
if [ `cat /etc/passwd | grep -Ev "nologin|shutdown|halt|sync" | grep -v "#" | wc -l` -eq 1 ]; then
	echo "root 이외 다른 사용자 계정이 존재하지 않음. ( su 명령어 사용 불필요) (N/A)" >> $Mk 2>&1
	chk 3
else
	if [ -e /etc/pam.d/su ]; then
		echo "[ /etc/pam.d/su 설정 값 ]" >> $Mk 2>&1
		echo "`cat /etc/pam.d/su`" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		if [ `cat /etc/pam.d/su | egrep "rootok|trust|required|pam_wheel.so" | grep -v "#" | wc -l` -eq 3 ]; then
			echo "pam_wheel 설정이 적용됨. (양호)" >> $Mk 2>&1
		else			
			echo "pam_wheel 설정 일부가 주석처리 되거나 존재하지 않음. (취약)" >> $Mk 2>&1
			chk 1
		fi
	else
		echo "/etc/pam.d/su 파일이 존재하지 않음. (취약)" >> $Mk 2>&1
	fi
	echo " " >> $Mk 2>&1
	aaa=0
	if [ `stat -L -c '%a' /usr/bin/su | cut -c 1` -gt 4 ]; then
		aaa=+1
	fi
	if [ `stat -L -c '%a' /usr/bin/su | cut -c 2` -gt 7 ]; then
		aaa=+1
	fi
	if [ `stat -L -c '%a' /usr/bin/su | cut -c 3` -gt 5 ]; then
		aaa=+1
	fi
	if [ `stat -L -c '%a' /usr/bin/su | cut -c 3` -gt 0 ]; then
		aaa=+1
	fi
	echo "[ /usr/bin/su 파일 ]" >> $Mk 2>&1
	echo "`ls -al /usr/bin/su`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	if [ $aaa != 0 ]; then
		echo "/usr/bin/su 파일의 퍼미션이 부적절함. (4750 권장) (취약)" >> $Mk 2>&1
		chk 1
	else
		echo "/usr/bin/su 파일의 퍼미션이 4750 이하임. (양호)" >> $Mk 2>&1
	fi
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U46() {
chk 0
echo "== [U-46]  패스워드 최소 길이 설정 ============================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>계정관리</분류>" >> $Mk 2>&1
echo "    <점검항목>패스워드 최소 길이 설정</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-46</주통코드>" >> $Mk 2>&1
echo "    <위험도>중</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 패스워드 최소 길이가 8자 이상으로 설정되어 있는 경우 양호. " >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
if [ -e /etc/login.defs ]; then
	echo "[ /etc/login.defs 설정 값 ]"	>> $Mk 2>&1
	echo "`cat /etc/login.defs | grep "PASS_MIN_LEN"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	if [ `cat /etc/login.defs | grep "PASS_MIN_LEN" | grep -v "#" | grep -v "Minimum" | awk -F' ' '{print$2}'` -lt 8 ]; then
		echo "PASS_MIN_LEN 설정이 '8'이하 이거나, 주석처리 됨. (취약)" >> $Mk 2>&1
		chk 1
	else
		echo "PASS_MIN_LEN 설정이 '8'이상임. (양호)" >> $Mk 2>&1
	fi
else
	echo "/etc/login.defs 파일이 존재하지 않음. (N/A)" >> $Mk 2>&1
	echo "CentOS7 이외 다른 OS는 추후에 추가될 예정입니다." >> $Mk 2>&1
	chk 3
fi 

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U47() {
chk 0
echo "== [U-47]  패스워드 최대 사용기간 설정 ========================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>계정관리</분류>" >> $Mk 2>&1
echo "    <점검항목>패스워드 최대 사용기간 설정</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-47</주통코드>" >> $Mk 2>&1
echo "    <위험도>중</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 패스워드 최대 사용기간이 90일 이하로 설정되어 있는 경우 양호. " >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
if [ -e /etc/login.defs ]; then
	echo "[ /etc/login.defs 설정 값 ]"	>> $Mk 2>&1
	echo "`cat /etc/login.defs | grep "PASS_MAX_DAYS"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	if [ `cat /etc/login.defs | grep "PASS_MAX_DAYS" | grep -v "#" | awk -F' ' '{print$2}'` -gt 90 ]; then
		echo "PASS_MAX_DAYS 설정이 '90'이상 이거나, 주석처리 됨. (취약)" >> $Mk 2>&1
		chk 1
	else
		echo "PASS_MAX_DAYS 설정이 '90' 이하임. (양호)" >> $Mk 2>&1
	fi
else
	echo "/etc/login.defs 파일이 존재하지 않음. (N/A)" >> $Mk 2>&1
	echo "CentOS7 이외 다른 OS는 추후에 추가될 예정입니다." >> $Mk 2>&1
	chk 3
fi 

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U48() {
chk 0
echo "== [U-48]  패스워드 최소 사용기간 설정 ========================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>계정관리</분류>" >> $Mk 2>&1
echo "    <점검항목>패스워드 최소 사용기간 설정</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-48</주통코드>" >> $Mk 2>&1
echo "    <위험도>중</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 패스워드 최소 사용기간이 1일 이상으로 설정되어 있는 경우 양호. " >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
if [ -e /etc/login.defs ]; then
	echo "[ /etc/login.defs 설정 값 ]"	>> $Mk 2>&1
	echo "`cat /etc/login.defs | grep "PASS_MIN_DAYS"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	if [ `cat /etc/login.defs | grep "PASS_MIN_DAYS" | grep -v "#" | awk -F' ' '{print$2}'` -eq 0 ]; then
		echo "PASS_MIN_DAYS 설정이 '1'미만 이거나, 주석처리 됨. (취약)" >> $Mk 2>&1
		chk 1
	else
		echo "PASS_MIN_DAYS 설정이 '1' 이상임. (양호)" >> $Mk 2>&1
	fi
else
	echo "/etc/login.defs 파일이 존재하지 않음. (N/A)" >> $Mk 2>&1
	echo "CentOS7 이외 다른 OS는 추후에 추가될 예정입니다." >> $Mk 2>&1
	chk 3
fi 

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U49() {
chk 0
echo "== [U-49]  불필요한 계정 제거 =================================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>계정관리</분류>" >> $Mk 2>&1
echo "    <점검항목>불필요한 계정 제거</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-49</주통코드>" >> $Mk 2>&1
echo "    <위험도>하</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 불필요한 계정이 존재하지 않는 경우 양호. " >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
if [ `cat /etc/passwd | egrep "lp|uucp|nuucp" | wc -l` -gt 0 ]; then
	echo "`cat /etc/passwd | egrep "lp|uucp|nuucp"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	echo "lp, uucp, nuucp 계정들은 삭제하는 것을 권고. (취약)" >> $Mk 2>&1
	echo "※ 해당 계정은 2021 KISA 주요정보통신기반시설 기술적 취약점 분석평가 상세 가이드에서 삭제하는 것을 권고하지만, 일부 서비스에 영향이 미칠 우려가 있어 충분한 검토 및 테스트 후에 삭제하는 것을 권고드립니다.  -해당 계정들에 대한 설명은 151p 참조"  >> $Mk 2>&1
	chk 1
else
	echo "불필요한 계정이 존재하지 않음. (양호)" >> $Mk 2>&1
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U50() {
chk 0
echo "== [U-50]  관리자 그룹에 최소한의 계정 포함 ===================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>계정관리</분류>" >> $Mk 2>&1
echo "    <점검항목>관리자 그룹에 최소한의 계정 포함</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-50</주통코드>" >> $Mk 2>&1
echo "    <위험도>하</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 관리자 그룹에 불필요한 계정이 등록되어 있지 않은 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
echo "[ /etc/group 파일의  root 그룹 ]" >> $Mk 2>&1
echo "`cat /etc/group | grep "root"`" >> $Mk 2>&1
echo " " >> $Mk 2>&1
if [ `cat /etc/group | grep "root" | egrep "test|Test|TEST" | wc -l` -gt 0 ]; then
	echo "root 그룹에 테스트 계정이 존재함. (취약)" >> $Mk 2>&1
	chk 1
else
	echo "root 그룹에 테스트 계정이 존재하지 않음. (양호)" >> $Mk 2>&1
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U51() {
chk 0
echo "== [U-51]  계정이 존재하지 않는 GID 금지 ======================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>계정관리</분류>" >> $Mk 2>&1
echo "    <점검항목>계정이 존재하지 않는 GID 금지</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-51</주통코드>" >> $Mk 2>&1
echo "    <위험도>하</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 시스템 관리나 운용에 불필요한 그룹이 삭제 되어있는 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
echo "검사 대상 : " >> $Mk 2>&1
echo "/etc/passwd 파일에서 UID가 1000이상인 일반사용자 계정" >> $Mk 2>&1
echo "/etc/group 파일에서 GID가 1000이상인 일반사용자 그룹" >> $Mk 2>&1
echo " " >> $Mk 2>&1
rm -rf ./passList.txt
rm -rf ./groupList.txt
awk -F: '$3 >= 1000 && $3 < 65534 { print $1 }' /etc/passwd >> ./passList.txt
awk -F: '$3 >= 1000 && $3 < 65534 { print $1 }' /etc/group  >> ./groupList.txt

if [ `grep -vf ./passList.txt ./groupList.txt | wc -l` -gt 0 ]; then
	echo "[ 계정이 존재하지 않는 그룹 리스트 ]" >> $Mk 2>&1
	echo "`grep -vf ./passList.txt ./groupList.txt`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1  
	echo "해당 그룹들은 존재하지만, 등록된 계정이 없습니다. (취약)" >> $Mk 2>&1
	chk 1
else
	echo "불필요한 그룹이 존재하지 않음. (양호)" >> $Mk 2>&1  
fi
rm -rf ./passList.txt
rm -rf ./groupList.txt
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U52() {
chk 0
echo "== [U-52]  동일한 UID 금지 ====================================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>계정관리</분류>" >> $Mk 2>&1
echo "    <점검항목>동일한 UID 금지</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-52</주통코드>" >> $Mk 2>&1
echo "    <위험도>중</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 동일한 UID로 설정된 사용자 계정이 존재하지 않는 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

if [ `awk -F: 'seen[$3]++ { print "Duplicate UID:", $3, "for user:", $1 }' /etc/passwd | wc -l` -gt 0 ]; then
	echo "`awk -F: 'seen[$3]++ { print "Duplicate UID:", $3, "for user:", $1 }' /etc/passwd`" >> $Mk 2>&1
	echo "동일한 UID로 설정된 계정이 존재함. (취약)" >> $Mk 2>&1
	chk 1
else
	echo "동일한 UID로 설정된 계정이 존재하지 않음. (양호)" >> $Mk 2>&1
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}


U53() {
chk 0
echo "== [U-53]  사용자 shell 점검 ==================================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>계정관리</분류>" >> $Mk 2>&1
echo "    <점검항목>사용자 shell 점검</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-53</주통코드>" >> $Mk 2>&1
echo "    <위험도>하</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin) 쉘이 부여되어 있는 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
list1=`cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^operator|^games|^gopher" | grep -vE "admin|system"
`
echo "검사대상 :" >> $Mk 2>&1
echo "$list1" >> $Mk 2>&1
aa=0
for bb in $list1
do
	if [[ `echo $bb | awk -F':' '{ print $NF }'` == "/sbin/nologin" || `echo $bb | awk -F':' '{ print $NF }'` == "/bin/false" ]]; then
		chk 0
	else
		echo "$bb" >> $Mk 2>&1
		aa=+1		
	fi
done
echo " " >> $Mk 2>&1
if [ $aa -gt 0 ]; then
	echo "로그인이 필요하지 않은 계정에 쉘이 부여됨. (취약)" >> $Mk 2>&1
	echo "해당 계정에 '/sbin/nologin' 또는 '/bin/false' 부여 권장." >> $Mk 2>&1
	chk 1
else
	echo "로그인이 필요하지 않은 계정에 불필요한 쉘이 부여되지 않음. (양호)" >> $Mk 2>&1
	chk 0
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U54() {
chk 0
echo "== [U-54]  Session Timeout 설정 ================================================"
echo "  <row>" >> $Mk 2>&1
echo "    <분류>계정관리</분류>" >> $Mk 2>&1
echo "    <점검항목>Session Timeout 설정</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-54</주통코드>" >> $Mk 2>&1
echo "    <위험도>하</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : Session Timeout이 600초 이하로 설정되어 있는 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

if [ -e /etc/profile ]; then
	echo "[ /etc/profile 설정 값 ]" >> $Mk 2>&1
	echo "`cat /etc/profile | egrep "export|TMOUT"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	if [ `cat /etc/profile | grep "TMOUT=" | grep -v "#" | wc -l` -gt 0 ]; then
		if [ `cat /etc/profile | grep "export" | grep "TMOUT" | grep -v "#" | wc -l` -gt 0 ]; then
			if [ `cat /etc/profile | grep "TMOUT=" | grep -v "#" | awk -F'=' '{print$2}'` -lt 601 ]; then
				echo "600초 이하으로 설정됨. (양호)" >> $Mk 2>&1
			else
				chk 1
				echo "600초 이상으로 설정됨. (취약)" >> $Mk 2>&1
				echo "-KISA 권고 600초 이하 설정." >> $Mk 2>&1
			fi
		else
			chk 1
			echo "export TMOUT 설정이 존재하지 않거나, 주석처리 됨. (취약)" >> $Mk 2>&1
		fi
	else
		chk 1
		echo "TMOUT= 설정이 존재하지 않거나, 주석처리 됨. (취약)" >> $Mk 2>&1
	fi
else
	echo "/etc/profile 파일이 존재하지않음">> $Mk 2>&1
	if [ -e /etc/csh.login ]; then
		echo "/etc/profile 파일이 존재하지않아 /etc/csh.loglin 파일을 검사합니다." >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		echo "[ /etc/csh.login 설정 값 ]" >> $Mk 2>&1
		echo "`cat /etc/csh.login | egrep "set|autologout"`" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		if [ `cat /etc/csh.login | grep "set" | grep "autologout" | grep -v "#" | wc -l` -gt 0 ]; then
			if [ `cat /etc/csh.login | grep "set" | grep "autologout" | grep -v "#" | awk -F'=' '{print$2}'` -gt 9 ]; then
				echo "set autologout 설정이 10 이상임. (양호)" >> $Mk 2>&1
			else
				chk 1
				echo "set autologout 설정이 10 이하임. (취약)" >> $Mk 2>&1
			fi
		else
			chk 1
			echo "set autoulogout 설정이 존재하지 않거나, 주석처리 됨. (취약)" >> $Mk 2>&1
		fi
	else
		chk 3
		echo "/etc/csh.login 파일이 존재하지 않습니다. 검사불가 (N/A)" >> $Mk 2>&1
	fi
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}



U55() {
chk 0
echo "== [U-55]  hosts.lpd 파일 소유자 및 권한 설정 =================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>파일 및 디렉토리 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>hosts.lpd 파일 소유자 및 권한 설정</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-55</주통코드>" >> $Mk 2>&1
echo "    <위험도>하</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : hosts.lpd 파일이 삭제되어 있거나, 불가피하게 hosts.lpd 파일을 사용할 시 파일의 소유자가 root이고 권한이 600인 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

aa=0
if [ -e /etc/hosts.lpd ]; then
	echo "[ /etc/hosts.lpd 파일 ]" >> $Mk 2>&1
	echo "`ls -al /etc/hosts.lpd`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	if [ `stat -L -c '%a' /etc/hosts.lpd | cut -c 1` -gt 6 ]; then
		aa=+1
	fi
	if [ `stat -L -c '%a' /etc/hosts.lpd | cut -c 2` -gt 0 ]; then
		aa=+1
	fi
	if [ `stat -L -c '%a' /etc/hosts.lpd | cut -c 3` -gt 0 ]; then
		aa=+1
	fi
	if [ $aa -gt 0 ]; then
		chk 1
		echo "해당 파일의 퍼미션이 부적절함. 600이하 권고. (취약)" >> $Mk 2>&1
	else
		echo "해당 파일의 퍼미션이 600이하임. (양호)" >> $Mk 2>&1
	fi
	if [ `ls -al /etc/hosts.lpd | awk -F' ' '{print$3}'` != "root" ]; then
		chk 1
		echo "해당 파일의 소유자가 root가 아님. (취약)" >> $Mk 2>&1
	else
		echo "해당 파일의 소유자가 root임. (양호)" >> $Mk 2>&1
	fi
else
	echo "/etc/hosts.lpd 파일이 존재하지 않음. (양호)" >> $Mk 2>&1
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U56() {
chk 0
echo "== [U-56]  UMASK 설정 관리 ====================================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>파일 및 디렉토리 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>UMASK 설정 관리</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-56</주통코드>" >> $Mk 2>&1
echo "    <위험도>중</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : UMASK 값이 022 이상으로 설정된 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
echo "[ UMASK 설정 값 ]" >> $Mk 2>&1
echo "`umask`" >> $Mk 2>&1
echo " " >> $Mk 2>&1
aa=0
if [ `umask | cut -c 3` -lt 2 ]; then
	aa=+1
fi
if [ `umask | cut -c 4` -lt 2 ]; then
	aa=+1
fi
if [ $aa -gt 0 ]; then
	echo "UMASK 값이 022 이하임. (취약)" >> $Mk 2>&1
	chk 1
else
	echo "UMASK 값이 022 이상임. (양호)" >> $Mk 2>&1
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U57() {
chk 0
echo "== [U-57]  홈디렉토리 소유자 및 권한 설정 ======================================"
echo "  <row>" >> $Mk 2>&1
echo "    <분류>파일 및 디렉토리 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>홈디렉토리 소유자 및 권한 설정</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-57</주통코드>" >> $Mk 2>&1
echo "    <위험도>중</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 홈 디렉터리 소유자가 해당 계정이고, 타 사용자 쓰기 권한이 제거된 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

echo "검사대상: (UID 1000이상의 일반사용자 계정)" >> $Mk 2>&1
echo "`awk -F: '$3 >= 1000 && $3 < 65534 { print }' /etc/passwd`" >> $Mk 2>&1
echo " " >> $Mk 2>&1
username=`awk -F: '$3 >= 1000 && $3 < 65534 { print $1 }' /etc/passwd`
aa=0

for bb in $username; 
do
   if [ "$(stat -c '%U' /home/$bb)" != "$bb" ]; then
	 echo "`ls -ald /home/$bb`" >> $Mk 2>&1
     echo "$bb 계정의 홈디렉터리 소유자가 해당 계정이 아님. (취약)" >> $Mk 2>&1
	 echo " " >> $Mk 2>&1
	 aa=+1
	 chk 1
   fi
done

if [ $aa -eq 0 ]; then
	echo "홈 디렉터리의 소유자가 모두 해당 계정임. (양호)" >> $Mk 2>&1
fi
aa=0

for bb in $username; 
do
    if [ `ls -ald /home/$bb | cut -c 9` != "-" ]; then
		echo "`ls -ald /home/$bb`" >> $Mk 2>&1
       echo "$bb 계정의 홈디렉터리에 타 사용자 쓰기 권한이 부여됨. (취약)" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		chk 1
		aa=+1
    fi
done
if [ $aa -eq 0 ]; then
	echo "홈 디렉터리에 타 사용자 쓰기 권한이 부여된 계정이 존재하지 않음. (양호)" >> $Mk 2>&1
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U58() {
chk 0
echo "== [U-58]  홈디렉토리로 지정한 디렉토리의 존재 관리 ============================"
echo "  <row>" >> $Mk 2>&1
echo "    <분류>파일 및 디렉토리 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>홈디렉토리로 지정한 디렉토리의 존재 관리</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-58</주통코드>" >> $Mk 2>&1
echo "    <위험도>중</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 홈 디렉터리가 존재하지 않는 계정이 발견되지 않는 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

echo "검사대상: (UID 1000이상의 일반사용자 계정)" >> $Mk 2>&1
echo "`awk -F: '$3 >= 1000 && $3 < 65534 { print }' /etc/passwd`" >> $Mk 2>&1
echo " " >> $Mk 2>&1

username=`awk -F: '$3 >= 1000 && $3 < 65534 { print $1 }' /etc/passwd`
aa=0

for bb in $username; 
do
	if [ `cat /etc/passwd | grep -w "$bb" | awk -F':' '{print$6}'` = "/" ]; then
		echo "`cat /etc/passwd | grep -w "$bb"`" >> $Mk 2>&1
		echo "$bb 계정의 홈 디렉터리가 지정되지 않음. (취약)" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		aa=+1
		chk 1
	fi
done
if [ $aa -eq 0 ]; then
	echo "홈 디렉터리가 존재하지 않는 계정이 존재하지 않음. (양호)" >> $Mk 2>&1
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}


U59() {
rm -rf ./U-59.txt
chk 0
if [[ "$wwd" == "Y" || "$wwd" == "y" ]]; then
	echo "== [U-59]  숨겨진 파일 및 디렉토리 검색 및 제거 ================================"
else
	echo "== [U-59]  숨겨진 파일 및 디렉토리 검색 및 제거 ==============[ N/A ]==========="
fi
echo "  <row>" >> $Mk 2>&1
echo "    <분류>파일 및 디렉토리 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>숨겨진 파일 및 디렉토리 검색 및 제거</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-59</주통코드>" >> $Mk 2>&1
echo "    <위험도>하</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 홈 디렉터리가 존재하지 않는 계정이 발견되지 않는 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
if [[ "$wwd" == "Y" || "$wwd" == "y" ]]; then
	rm -rf ./U-59.txt
	echo "[ 숨김 파일 목록 : ]" >> ./U-59.txt	
	find / -type f -name ".*" >> ./U-59.txt
	echo "#####################################################################">> ./U-59.txt
	echo " " >> ./U-59.txt
	echo "[ 숨김 디렉터리 목록 : ]" >> ./U-59.txt
	find / -type d -name ".*" >> ./U-59.txt
	
	if [ `head -5 ./U-59.txt | wc -l` -gt 4 ]; then
		echo "숨겨진 파일 또는 디렉토리가 존재함." >> $Mk 2>&1
		echo "U-59.txt 파일 확인필요" >> $Mk 2>&1
		u59file=+1
		chk 2
	fi	
else
	echo "전역변수 검사를 선택하지 않음. (N/A)" >> $Mk 2>&1
	chk 3
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U60() {
chk 0
echo "== [U-60]  ssh 원격접속 허용 ==================================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>ssh 원격접속 허용</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-60</주통코드>" >> $Mk 2>&1
echo "    <위험도>중</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 원격 접속 시  SSH 프로토콜을 사용하는 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

if [ `ps -ef | grep "sshd" | grep -v "grep" | wc -l` -gt 0 ]; then
	echo "[ 프로세스 현황 ]" >> $Mk 2>&1
	echo "`ps -ef | grep "sshd" | grep -v "grep"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	echo "ssh 프로토콜 사용 중. (양호)" >> $Mk 2>&1
else
	echo "ssh 프로토콜을 사용하지 않음. (취약)" >> $Mk 2>&1
	chk 1
fi
if [ `systemctl status telnet.socket 2>/dev/null | wc -l` -gt 0 ]; then
	echo "telnet을  사용하고 있음. (취약)" >> $Mk 2>&1
	chk 1
else
	echo "telnet을 사용하지 않음. (양호)" >> $Mk 2>&1
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U61() {
chk 0
echo "== [U-61]  ftp 서비스 확인 ====================================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>ftp 서비스 확인</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-61</주통코드>" >> $Mk 2>&1
echo "    <위험도>하</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : FTP 서비스가 비활성화 되어있는 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
if [ `ps -ef | egrep "vsftpd|proftp" | grep -v "grep" | wc -l` -gt 0 ]; then
	echo "[ 프로세스 현황 ]" >> $Mk 2>&1
	echo "`ps -ef | egrep "vsftpd|proftp" | grep -v "grep"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	echo "ftp 서비스가 활성화 됨. (취약)" >> $Mk 2>&1
	chk 1
else
	echo "ftp 서비스를 사용하지 않음. (양호)" >> $Mk 2>&1
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U62() {
chk 0
echo "== [U-62]  ftp 계정  shell 제한 ================================================"
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>ftp 계정 shell 제한</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-62</주통코드>" >> $Mk 2>&1
echo "    <위험도>중</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : ftp 계정에 /bin/false 쉘이 부여되어 있는 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

if [ `ps -ef | grep -E "vsftpd|proftpd" | grep -v "grep" | wc -l` -gt 0 ]; then
	if [ `cat /etc/passwd | grep "ftp" | wc -l` -gt 0 ]; then
		cat /etc/passwd | grep "ftp" >> $Mk 2>&1
		echo " " >> $Mk 2>&1

		list1=`cat /etc/passwd | grep "ftp" | awk -F':' '{print$7}'`
		aa=0
		for bb in $list1;
		do
			if [[ "$bb" != "/sbin/nologin" && "$bb" != "/bin/false" ]]; then
				aa=+1
			fi 
		done
		if [ $aa -gt 0 ]; then
			echo "ftp 계정에 쉘이 부여됨. (취약)" >> $Mk 2>&1
			chk 1
		else
			echo "ftp 계정에 쉘이 부여되지 않음. (양호)" >> $Mk 2>&1
		fi
	else
		echo "ftp 계정이 존재하지 않음. (양호)" >> $Mk 2>&1
	fi
else
	echo "FTP 서비스를 사용하지 않음. (양호)" >> $Mk 2>&1
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U63() {
chk 0
echo "== [U-63]  ftpusers 파일 소유자 및 권한 설정 ==================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>ftpusers 파일 소유자 및 권한 설정</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-63</주통코드>" >> $Mk 2>&1
echo "    <위험도>하</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : ftpusers 파일의 소유자가  root이고, 권한이 640이하인 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

if [ `ps -ef | grep -E "vsftpd|proftpd" | grep -v "grep" | wc -l` -gt 0 ]; then
	if [ -e /etc/vsftpd/ftpusers ]; then
		echo "[ /etc/vsftpd/ftpusers 파일 ]" >> $Mk 2>&1
		echo "`ls -al /etc/vsftpd/ftpusers`" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		if [ `ls -al /etc/vsftpd/ftpusers | awk -F' ' '{print$3}'` != "root" ]; then
			echo "/etc/vsftpd/ftpusers 파일 소유자가 root가 아님. (취약)" >> $Mk 2>&1
			chk 1
			echo " " >> $Mk 2>&1
		else
			echo "/etc/vsftpd/ftpusers 파일 소유자가 root임. (양호)" >> $Mk 2>&1
			echo " " >> $Mk 2>&1
		fi
		aa=0
		if [ `stat -L -c '%a' /etc/vsftpd/ftpusers | cut -c 1` -gt 6 ]; then
			aa=+1
		fi
		if [ `stat -L -c '%a' /etc/vsftpd/ftpusers | cut -c 2` -gt 4 ]; then
			aa=+1
		fi	
		if [ `stat -L -c '%a' /etc/vsftpd/ftpusers | cut -c 3` -gt 0 ]; then
			aa=+1
		fi
		if [ $aa -gt 0 ]; then
			echo "/etc/vsftpd/ftpusers 파일 퍼미션이 부적절함. 640이하 권고 (취약)" >> $Mk 2>&1
			chk 1
		else
			echo "/etc/vsftpd/ftpusers 파일 퍼미션이 640이하임. (양호)" >> $Mk 2>&1
		fi
	else
		echo "/etc/vsftpd/ftpusers 파일이 존재하지 않음." >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		if [ -e /etc/ftpusers ]; then
			echo "[ /etc/ftpusers 파일 ]" >> $Mk 2>&1
			echo "`ls -al /etc/ftpusers`" >> $Mk 2>&1
			echo " "
			if [ `ls -al /etc/ftpusers | awk -F' ' '{print$3}'` != "root" ]; then
				echo "/etc/ftpusers 파일 소유자가 root가 아님. (취약)" >> $Mk 2>&1
				chk 1
				echo " " >> $Mk 2>&1
			else
				echo "/etc/ftpusers 파일 소유자가 root임. (양호)" >> $Mk 2>&1
				echo " " >> $Mk 2>&1
			fi
			aa=0
			if [ `stat -L -c '%a' /etc/ftpusers | cut -c 1` -gt 6 ]; then
				aa=+1
			fi
			if [ `stat -L -c '%a' /etc/ftpusers | cut -c 2` -gt 4 ]; then
				aa=+1
			fi	
			if [ `stat -L -c '%a' /etc/ftpusers | cut -c 3` -gt 0 ]; then
				aa=+1
			fi
			if [ $aa -gt 0 ]; then
				echo "/etc/ftpusers 파일 퍼미션이 부적절함. 640이하 권고 (취약)"  >> $Mk 2>&1
				chk 1
			else
				echo "/etc/ftpusers 파일 퍼미션이 640이하임. (양호)" >> $Mk 2>&1
			fi
		else
			echo "/etc/ftpusers 파일이 존재하지 않음." >> $Mk 2>&1
		fi
	fi
else
	echo "FTP 서비스를 사용하지 않음. (양호)" >> $Mk 2>&1
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
	}

U64() {
chk 0
echo "== [U-64]  ftpusers 파일 설정(FTP 서비스 root 계정 접근제한) ==================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>ftpusers 파일 설정(FTP 서비스 root 계정 접근제한)</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-64</주통코드>" >> $Mk 2>&1
echo "    <위험도>중</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : FTP 서비스가 비활성화 되어 있거나, 활성화 시  root 계정 접속을 차단한 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

if [ `ps -ef | grep "vsftpd" | grep -v "grep" | wc -l` -gt 0 ]; then
	echo "[ vsftpd 서비스 사용중 ]" >> $Mk 2>&1
	echo "`ps -ef | egrep "vsftpd" | grep -v "grep"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	
	
	if [ -f /etc/vsftpd/ftpusers ]; then
		echo "[ /etc/vsftpd/ftpusers 파일]" >> $Mk 2>&1
		cat /etc/vsftpd/ftpusers >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		if [ `cat /etc/vsftpd/ftpusers | grep "root" | grep -v "#" | wc -l` -gt 0 ]; then
			echo "차단 목록에 root 계정이 등록됨. (양호)" >> $Mk 2>&1
		else
			echo "차단 목록에 root 계정이 등록되지 않음. (취약)" >> $Mk 2>&1
			chk 1
		fi
	else
		echo "/etc/vsftpd/ftpusers 파일이 존재하지 않음. 확인불가 -> 인터뷰" >> $Mk 2>&1
		chk 4
	fi
fi

if [ `ps -ef | grep "proftpd" | grep -v "grep" | wc -l` -gt 0 ]; then
	echo "[ proftpd 서비스 사용중 ]" >> $Mk 2>&1
	echo "`ps -ef | egrep "proftpd" | grep -v "grep"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	if [ -f /etc/proftpd.conf ]; then
		if [ `cat /etc/proftpd.conf | grep "RootLogin" | grep -v "#" | awk -F' ' '{print$2}' | grep "on" | wc -l` -gt 0 ]; then
			echo "[ /etc/proftpd.conf 설정 값]" >> $Mk 2>&1
			cat /etc/proftpd.conf | grep "RootLogin" >> $Mk 2>&1
			echo " " >> $Mk 2>&1
			echo "root 로그인이 허용됨. (취약)" >> $Mk 2>&1
			chk 1
		else
			echo "root 로그인이 허용되지 않음. (양호)" >> $Mk 2>&1
		fi
	else
		echo "/etc/proftpd.conf 파일이 존재하지 않음. 확인불가 -> 인터뷰" >> $Mk 2>&1
		chk 4
	fi
fi

if [ `ps -ef | egrep "vsftpd|proftpd" | grep -v "grep" | wc -l` -eq 0 ]; then
	echo "ftp 서비스가 활성화 되지 않음. (양호)" >> $Mk 2>&1
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U65() {
chk 0
echo "== [U-65]  at 서비스 권한 설정 ================================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>at 서비스 권한 설정</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-65</주통코드>" >> $Mk 2>&1
echo "    <위험도>중</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : at 명령어 일반사용자 금지 및 at 관련 파일 권한이 640 이하인 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

echo "`ls -al /usr/bin/at`" >> $Mk 2>&1
if [ `ls -al /usr/bin/at | cut -c 10` != "-" ]; then
	echo "/usr/bin/at 명령어에 일반사용자 실행 권한이 허용됨. (취약)" >> $Mk 2>&1
	chk 1
else
	echo "/usr/bin/at 명령어에 일반사용자 실행 권한이 제거됨. (양호)" >> $Mk 2>&1
fi
echo " " >> $Mk 2>&1
if [ -e /etc/at.deny ]; then 
	echo "`ls -al /etc/at.deny`" >> $Mk 2>&1
	aa=0
	if [ `stat -L -c '%a' /etc/at.deny | cut -c 1` -gt 6 ]; then
		aa=+1
	fi
	if [ `stat -L -c '%a' /etc/at.deny | cut -c 2` -gt 4 ]; then
		aa=+1
	fi
	if [ `stat -L -c '%a' /etc/at.deny | cut -c 3` -gt 0 ]; then
		aa=+1
	fi
	if [ $aa -gt 0 ]; then
		echo "/etc/at.deny 파일 퍼미션이 640 이상임. (취약)" >> $Mk 2>&1 
		chk 1
	else		
		echo "/etc/at.deny 파일 퍼미션이 640 이하임. (양호)" >> $Mk 2>&1 
	fi
else
	echo "/etc/at.deny 파일이 존재하지 않음." >> $Mk 2>&1
fi
echo " " >> $Mk 2>&1 
if [ -e /etc/at.allow ]; then 
	echo "`ls -al /etc/at.allow`" >> $Mk 2>&1
	aa=0
	if [ `stat -L -c '%a' /etc/at.allow  | cut -c 1` -gt 6 ]; then
		aa=+1
	fi
	if [ `stat -L -c '%a' /etc/at.allow  | cut -c 2` -gt 4 ]; then
		aa=+1
	fi
	if [ `stat -L -c '%a' /etc/at.allow  | cut -c 3` -gt 0 ]; then
		aa=+1
	fi
	if [ $aa -gt 0 ]; then
		echo "/etc/at.allow  파일 퍼미션이 640 이상임. (취약)" >> $Mk 2>&1 
		chk 1
	else		
		echo "/etc/at.allow  파일 퍼미션이 640 이하임. (양호)" >> $Mk 2>&1
	fi
else
	echo "/etc/at.allow 파일이 존재하지 않음." >> $Mk 2>&1
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}	



U66() {
chk 0
echo "== [U-66]  SNMP 서비스 구동 점검 ==============================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>SNMP 서비스 구동 점검</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-66</주통코드>" >> $Mk 2>&1
echo "    <위험도>중</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : SNMP 서비스를 사용하지 않는 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
if [ `ps -ef | grep "snmp" | grep -v "grep" | wc -l` -gt 0 ]; then
	echo "[ 프로세스 현황 ]"	>> $Mk 2>&1
	echo "`ps -ef | grep "snmp" | grep -v "grep"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	echo "snmp 서비스가 실행중임. (취약)" >> $Mk 2>&1
	chk 1
else
	echo "snmp 서비스가 활성화 되지 않음. (양호)" >> $Mk 2>&1
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}


U67() {
chk 0
echo "== [U-67]  SNMP 서비스 Community String의 복잡성 설정 =========================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>SNMP 서비스 Community String의 복잡성 설정</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-67</주통코드>" >> $Mk 2>&1
echo "    <위험도>중</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : SNMP Community 이름이 public, private 이 아닌 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
if [ `ps -ef | grep "snmp" | grep -v "grep" | wc -l` -gt 0 ]; then
	echo "[ 프로세스 현황 ]"	>> $Mk 2>&1
	echo "`ps -ef | grep "snmp" | grep -v "grep"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	echo "snmp 서비스가 실행중임." >> $Mk 2>&1
	if [ -e /etc/snmp/snmpd.conf ]; then
		if [ `cat /etc/snmp/snmpd.conf | egrep "com2sec|default" | grep -E "public|private" | wc -l` -gt 0 ]; then
			echo "[ /etc/snmp/snmpd.conf 설정 값 ]" >> $Mk 2>&1
			echo "`cat /etc/snmp/snmpd.conf | egrep "com2sec|default" | grep -E "public|private"`" >> $Mk 2>&1
			echo " " >> $Mk 2>&1
			echo "커뮤니티명이 public 또는 private 로 설정되어 있음. (취약)" >> $Mk 2>&1
			chk 1
		else
			echo "커뮤니티명이 public 또는 private 로 설정되지 않음. (양호)" >> $Mk 2>&1
		fi
	else
		echo "/etc/snmp/snmpd.conf 파일이 존재하지 않음. 확인불가 -> 인터뷰" >> $Mk 2>&1
		chk 4
	fi
else
	echo "snmp 서비스가 활성화 되지 않음. (양호)" >> $Mk 2>&1
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U68() {
chk 0
echo "== [U-68]  로그온 시 경고 메시지 제공 =========================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>로그온 시 경고 메시지 제공</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-68</주통코드>" >> $Mk 2>&1
echo "    <위험도>하</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 서버 및 Telnet, FTP, SMTP, DNS 서비스에 로그온 메시지가 설정되어 있는 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

if [ -e /etc/motd ]; then
	echo "/etc/motd 서버 로그온 시 메시지가 존재함. (양호)" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
else
	echo "/etc/motd 서버 로그온 메시지가 존재하지 않음. (취약)" >> $Mk 2>&1
	chk 1
	echo " " >> $Mk 2>&1
fi

if [ `systemctl status telnet.socket 2>/dev/null | wc -l` -gt 0 ]; then
	if [ -e /etc/issue.net ]; then
		echo "telnet 서비스 사용중 - >  /etc/issue.net 배너 메시지 파일이 존재함. (양호)" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
	else
		echo "telnet 서비스 사용중 - >  /etc/issue.net 배너 메시지 파일이 존재하지 않음. (취약)" >> $Mk 2>&1
		chk 1
		echo " " >> $Mk 2>&1	
	fi
fi

if [ `ps -ef | grep "vsftpd" | grep -v "grep" | wc -l` -gt 0 ]; then
	if [ -e /etc/vsftpd/vsftpd.conf ]; then
		echo "[ /etc/vsftpd/vsftpd.conf 설정 값 ]" >> $Mk 2>&1
		echo "`cat /etc/vsftpd/vsftpd.conf | grep "ftpd_banner"`" >> $Mk 2>&1
		echo " " >> $Mk 2>&1	
		if [ `cat /etc/vsftpd/vsftpd.conf | grep "ftpd_banner" | grep -v "#" | wc -l` -gt 0 ]; then
			echo "vsftpd 서비스 사용중 -> /etc/vsftpd/vsftpd.conf 설정에 배너 메시지가 존재함. (양호)" >> $Mk 2>&1
		else
			echo "vsftpd 서비스 사용중 -> /etc/vsftpd/vsftpd.conf 설정에 배너 메시지가 존재하지 않음. (취약)" >> $Mk 2>&1
			chk 1
		fi
	else
		echo "vsftpd 서비스를 사용중 -> /etc/vsftpd/vsftpd.conf 파일이 존재하지 않음." >> $Mk 2>&1
	fi
fi

if [ `ps -ef | grep "sendmail" | grep -v "grep" | wc -l` -gt 0 ]; then
	if [ -e /etc/mail/sendmail.cf ]; then
		echo "[ /etc/mail/sendmail.cf 설정 값 ]" >> $Mk 2>&1
		echo "`cat /etc/mail/sendmail.cf | grep 'GreetingMessage'`" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		if [ `cat /etc/mail/sendmail.cf | grep 'GreetingMessage="' | grep -v "#" | wc -l` -gt 0 ]; then
			echo "sendmail 서비스 사용중 -> /etc/mail/sendmail.cf 설정에 배너 메시지가 존재함. (양호)" >> $Mk 2>&1
		else
			echo "sendmail 서비스 사용중 -> /etc/mail/sendmail.cf 설정에 배너 메시지가 존재하지 않음. (취약)" >> $Mk 2>&1
			chk 1
		fi
	else
		echo "sendmail 서비스 사용중 -> /etc/mail/sendmail.cf 파일이 존재하지 않음" >> $Mk 2>&1
	fi
fi
echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U69() {
chk 0
echo "== [U-69]  NFS 설정파일 접근권한 ==============================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>NFS 설정파일 접근권한</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-69</주통코드>" >> $Mk 2>&1
echo "    <위험도>중</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : NFS 접근제어 설정파일의 소유자가 root이고, 권한이 644 이하인 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

if [ `ps -ef | egrep "nfs|statd|lockd" | grep -v "grep" | grep -v "kblockd" | wc -l` -gt 0 ]; then
	echo "[ NFS 서비스 실행중 ]" >> $Mk 2>&1
	echo "`ps -ef | egrep "nfs|statd|lockd" | grep -v "grep" | grep -v "kblockd"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	if [ -e /etc/exports ]; then
		echo "`ls -al /etc/exports`" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		if [ `ls -al /etc/exports | awk -F' ' '{print$3}'` = "root" ]; then
			echo "/etc/exprots 파일의 소유자가 root임. (양호)" >> $Mk 2>&1
		else
			echo "/etc/exports 파일의 소유자가 root가 아님. (취약)" >> $Mk 2>&1
			chk 1
		fi
		echo " " >> $Mk 2>&1	
		aa=0
		if [ `stat -L -c '%a' /etc/exports | cut -c 1` -gt 6 ]; then
			aa=+1
		fi
		if [ `stat -L -c '%a' /etc/exports | cut -c 2` -gt 4 ]; then
			aa=+1
		fi
		if [ `stat -L -c '%a' /etc/exports | cut -c 3` -gt 4 ]; then
			aa=+1
		fi
		if [ $aa -gt 0 ]; then
			echo "/etc/exports 파일의 퍼미션이 부적절함. (644이하 권고). (취약)" >> $Mk 2>&1
			chk 1
		else
			echo "/etc/exprots 파일의 퍼미션이 644 이하임. (양호)" >> $Mk 2>&1
		fi
	else
		echo "/etc/exports 파일이 존재하지 않음. 확인불가 -> 인터뷰" >> $Mk 2>&1
		chk 4
	fi
else
	echo "NFS 서비스를 사용하지 않음. (양호)" >> $Mk 2>&1
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U70() {
chk 0
echo "== [U-70]  expn, vrfy 명령어 제한 =============================================="
echo "  <row>" >> $Mk 2>&1
echo "    <분류>서비스 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>expn, vrfy 명령어 제한</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-70</주통코드>" >> $Mk 2>&1
echo "    <위험도>중</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : SMTP 서비스 미사용 또는, noexpn, novrfy 옵션이 설정되어 있는 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1

if [ `ps -ef | grep "sendmail" | grep -v "grep" | wc -l` -gt 0 ]; then
	echo "[ sendmail 프로세스 실행중 ]" >> $Mk 2>&1
	echo "`ps -ef | grep "sendmail" | grep -v "grep"`" >> $Mk 2>&1
	echo " " >> $Mk 2>&1
	if [ -e /etc/mail/sendmail.cf ]; then
		echo "[ /etc/mail/sendmail.cf 설정 값 ]" >> $Mk 2>&1
		echo "`cat /etc/mail/sendmail.cf | grep "PrivacyOptions"`" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		if [ `cat /etc/mail/sendmail.cf | grep "PrivacyOptions" | grep -E "novrfy|noexpn" | grep -v "#" | wc -l` -gt 0 ]; then
			echo "novrfy, noexpn 옵션이 설정되어 있음. (양호)" >> $Mk 2>&1
		else
			echo "novrfy, noexpn 옵션이 설정되지 않음. (취약)" >> $Mk 2>&1
			chk 1
		fi
	else
		echo "/etc/mail/sendmail.cf 파일이 존재하지 않음. 확인불가 -> 인터뷰" >> $Mk 2>&1
		chk 4
	fi
else
	echo "sendmail 서비스를 사용하지 않음. (양호)" >> $Mk 2>&1
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1
}

U72() {
chk 0
echo "== [U-72]  정책에 따른 시스템 로깅 설정 ========================================"
echo "  <row>" >> $Mk 2>&1
echo "    <분류>로그 관리</분류>" >> $Mk 2>&1
echo "    <점검항목>정책에 따른 시스템 로깅 설정</점검항목>" >> $Mk 2>&1
echo "    <주통코드>U-72</주통코드>" >> $Mk 2>&1
echo "    <위험도>하</위험도>" >> $Mk 2>&1
echo "    <점검내용>" >> $Mk 2>&1
echo "※ 기준 : 로그 기록 정책이 정책에 따라 설정되어 수립되어 있으며, 보안정책에 따라 로그를 남기고 있을 경우 양호." >> $Mk 2>&1
echo "______________________________________________________" >> $Mk 2>&1
echo "☞ 현황 :" >> $Mk 2>&1
if [ `ps -ef | grep "syslog" | grep -v "grep" | wc -l` -gt 0 ]; then
	echo "[ syslog 또는 rsyslog 실행 중 ]" >> $Mk 2>&1
	echo "`ps -ef | grep "syslog" | grep -v "grep"`" >> $Mk 2>&1
	echo " "
	if [ -e /etc/rsyslog.conf ]; then
		echo "[ /etc/rsyslog.conf 설정 값 ]" >> $Mk 2>&1
		echo "`cat /etc/rsyslog.conf | grep -v "#"`" >> $Mk 2>&1
		echo " " >> $Mk 2>&1
		if [ `cat /etc/rsyslog.conf | grep -v "#" | grep "*.emerg" | wc -l` -gt 0 ]; then
			echo "*.emerg 설정이 존재함. (양호)" >> $Mk 2>&1
		else
			echo "*.emerg 설정이 존재하지 않음. (취약)" >> $Mk 2>&1
			chk 1
		fi
		if [ `cat /etc/rsyslog.conf | grep -v "#" | grep "*.alert" | wc -l` -gt 0 ]; then
			echo "*.alert 설정이 존재함. (양호)" >> $Mk 2>&1
		else
			echo "*.alert 설정이 존재하지 않음. (취약)" >> $Mk 2>&1
			chk 1
		fi
	else
		if [ -e /etc/syslog.conf ]; then
			echo "[ /etc/syslog.conf 설정 값 ]" >> $Mk 2>&1
			echo "`cat /etc/syslog.conf | grep -v "#"`"
			echo " "
			if [ `cat /etc/syslog.conf | grep -v "#" | grep "*.emerg" | wc -l` -gt 0 ]; then
				echo "*.emerg 설정이 존재함. (양호)" >> $Mk 2>&1
			else
				echo "*.emerg 설정이 존재하지 않음. (취약)" >> $Mk 2>&1
				chk 1
			fi
			if [ `cat /etc/syslog.conf | grep -v "#" | grep "*.alert" | wc -l` -gt 0 ]; then
				echo "*.alert 설정이 존재함. (양호)" >> $Mk 2>&1
			else
				echo "*.alert 설정이 존재하지 않음. (취약)" >> $Mk 2>&1
				chk 1
			fi
		else
			echo "/etc/syslog.conf 또는 /etc/rsyslog.conf 파일이 존재하지 않음. 확인불가 -> 인터뷰" >> $Mk 2>&1
			chk 4
		fi
	fi
else
	echo "syslog 또는 rsyslog 서비스를 사용하지 않음. (취약)" >> $Mk 2>&1
	chk 1
fi

echo " " >> $Mk 2>&1
echo " </점검내용>" >> $Mk 2>&1
echo "    <결과>$chkk</결과>" >> $Mk 2>&1
echo "  </row>" >> $Mk 2>&1
echo " " >> $Mk 2>&1


}
		





INF
U01
U02
U03
U04
U05
U06
U07
U08
U09
U10
U11
U12
U13
U14
U15
U16
U17
U18
U19
U20
U21
U22
U23
U24
U25
U26
U27
U28
U29
U30
U31
U32
U33
U34
U42
U43
U44
U45
U46
U47
U48
U49
U50
U51
U52
U53
U54
U55
U56
U57
U58
U59
U60
U61
U62
U63
U64
U65
U66
U67
U68
U69
U70
U72
echo "=================================[  E  N  D  ]=================================="
echo "================================================================================"
echo "(결과파일) $Mk 파일을 확인해주세요. "
if [ $u06file -gt 0 ]; then
	echo "(참고파일) U-06_info.txt 파일을 확인해주세요."
fi
if [ $u15file -gt 0 ]; then
	echo "(참고파일) U-15_world_writable.txt 파일을 확인해주세요."
fi
if [ $u59file -gt 0 ]; then
	echo "(참고파일) U-59.txt 파일을 확인해주세요."
fi
echo "감사합니다."
echo "</rows>" >> $Mk 2>&1
