# author：Haixuwan
# update 2021.02.01
#!/bin/bash
echo "
------------------------------------------------------------------------------------------------------------------------------------


                     ██╗  ██╗ █████╗  ██████╗██╗  ██╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
                     ██║  ██║██╔══██╗██╔════╝██║ ██╔╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
                     ███████║███████║██║     █████╔╝     ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
                     ██╔══██║██╔══██║██║     ██╔═██╗     ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
                     ██║  ██║██║  ██║╚██████╗██║  ██╗    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
                     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

                                                   Brutehunter V1.0
                                                   Author:Haixuwan
------------------------------------------------------------------------------------------------------------------------------------
溯源报告：
/tmp/brutehunter/report
溯源高可疑IP地址路径：
/tmp/brutehunter/report/ip
------------------------------------------------------------------------------------------------------------------------------------
以下文件不存在：
"
# 创建报告文件夹: /tmp/brutehunter/report/ip
function mkfile(){
	mkdir /tmp/brutehunter/ >/dev/null 2>&1
	mkdir /tmp/brutehunter/report >/dev/null 2>&1
	mkdir /tmp/brutehunter/report/ip >/dev/null 2>&1
	chmod +x ./tmp/brutehunter >/dev/null 2>&1
	chmod +x ./tmp/brutehunter/report >/dev/null 2>&1
	chmod +x ./tmp/brutehunter/report/ip >/dev/null 2>&1
	dir="/tmp/brutehunter/report/ip"
}

# Flogin_ip() 筛选登录失败IP地址：
function Flogin_ip(){
#(1)登录日志模糊审计: /var/log/*secure*
#                  /var/log/*auth*
# 适用CentOS:（egrep '[0-9]+\.'过滤掉字段，只保留含有数字和.的数据）
	grep "Failed " /var/log/*secure*|awk '{print $13}'|egrep '[0-9]+\.'|sort -u > /tmp/brutehunter/report/ip/F_secure_login_ip.txt  # 查找登录失败的IP地址，将IP列表导为F-slogin_ip.txt(这里IP地址不够全):
  # 适用于Ubuntu:（ubuntu主机访问日志路径/var/log/auth.log,这里IP地址）
	grep "fail" /var/log/*auth*|awk '{print $10}'|sort -u > /tmp/brutehunter/report/ip/F_auth_login_ip.txt                          # 查找登录失败的IP地址，将IP列表导为F-slogin_ip.txt(这里IP地址不够全):
#(2)lastb查看全部登录失败用户的IP地址: /var/log/btmp
	lastb|awk '{print $3}'|egrep '([0-9]+\.)'|sort -u > /tmp/brutehunter/report/ip/F_btmp_login_ip.txt  # 全部用户登录失败的IP地址，存为/report/ip/F-aulogin_ip.txt(全部爆破失败的IP地址，这里的IP地址比较全，可以参考为爆破失败的IP地址)
#(3)审计messages事件日志（从syslog中记录信息）: /var/log/*messa*
	grep "Access denied" /var/log/*messa*|awk '{print $13}'|awk -F'@' '{print $NF}'|sed "s|'||g"|egrep '[0-9]+\.'|sort -u > /tmp/brutehunter/report/ip/F_messages_login_ip.txt # messages事件日志登录失败日志
#(4)审计audit.log系统存储日志项: /var/log/*audit*
	grep "fail" /var/log/audit/*audi*|awk '{print $11}'|egrep '[0-9]+\.'|sed 's/addr=//g'|sed 's/hostname=//g'|sort -u > /tmp/brutehunter/report/ip/F_audit_login_ip.txt  # audit系统存储日志中登录失败的IP地址
}

# Slogin_ip() 筛选登录成功的IP地址：
function Slogin_ip(){
#(1)当前登录日志模糊审计: /var/log/*secure*
#                     /var/log/*auth*
  # 适用于CentOS：（redhat类linux系统主机访问日志路径/var/log/secure,这里取IP地址）
	grep "Accept" /var/log/*secure*|awk '{print $11}'|sort -u > /tmp/brutehunter/report/ip/S_secure_login_ip.txt  # 查找登录成功的用户IP,将该IP列表导出为S_login_ip.txt
  # 适用于Ubuntu：（ubuntu主机访问日志路径/var/log/auth.log,这里IP地址）
	grep "Accept" /var/log/*auth*|awk '{print $11}'|sort -u > /tmp/brutehunter/report/ip/S_auth_login_ip.txt   # 查找登录成功的用户IP,将该IP列表导出为S_auth_ip.txt
#(2)登录用户日志审计记录: /var/log/wtmp
  # 查找当前登录用户记录IP地址，将IP列表导出为S_culogin_ip.txt(当前用户的历史登录IP,登录成功的)：
	who /var/log/*wtmp*|awk '{print $5}'|sort -u > /tmp/brutehunter/report/ip/S_currentuser_login_ip.txt
	sed -i "s/(//g" /tmp/brutehunter/report/ip/S_currentuser_login_ip.txt #删除S_culogin_ip.txt中的(
	sed -i "s/)//g" /tmp/brutehunter/report/ip/S_currentuser_login_ip.txt #删除S_culogin_ip.txt中的)
#(3)审计audit.log系统存储日志项: /var/log/*audit*
	grep "success" /var/log/audit/*audi*|awk '{print $11}'|egrep '[0-9]+\.'|sed 's/addr=//g'|sed 's/hostname=//g'|sort -u > /tmp/brutehunter/report/ip/S_audit_login_ip.txt # audit系统存储日志中登录成功的IP地址
#(4)用户最后一次登录成功IP地址：
  last|awk '{print $3}'|egrep '([0-9]+\.)'|sort -u > /tmp/brutehunter/report/ip/S_lastlog_ip.txt
}

# Combine_ip():  筛选的ip地址整合
function Combine_ip(){
#(1)将所有登录失败IP地址整合为F_ip.txt
  cd /tmp/brutehunter/report/ip/
  echo "
------------------------------------------------------------------------------------------------------------------------------------
                                                    暴力破解结果
"
  echo "
登录失败IP地址个数：（路径：/tmp/brutehunter/report/ip/F_ip.txt）"
  cat F_secure_login_ip.txt F_auth_login_ip.txt F_btmp_login_ip.txt F_messages_login_ip.txt F_audit_login_ip.txt|sort -u > F_ip.txt # 将四个失败登录IP地址文件汇总，去重,取登录失败IP地址合计总数
  cat F_ip.txt|wc -l
#(2)将所有登录成功IP地址整合为S_ip.txt
  echo "
登录成功IP地址个数：（路径：/tmp/brutehunter/report/ip/S_ip.txt）"
  cat S_secure_login_ip.txt S_auth_login_ip.txt S_currentuser_login_ip.txt S_audit_login_ip.txt S_lastlog_ip.txt|sort -u> S_ip.txt  # 将四个失败登录IP地址文件汇总，去重,取登录成功IP地址合计总数
  cat S_ip.txt|wc -l
#(3)将登录成功IP和失败IP匹配高可以登录地址
  cat F_ip.txt S_ip.txt|sort|uniq -d > risk_ip.txt # 取登录成功IP和登录失败IP集合交集
  echo "
经暴力破解入侵的高可疑IP地址个数："
  cat risk_ip.txt|wc -l # 显示成功入侵IP地址个数
  echo "
经暴力破解入侵的高可疑IP地址：（路径：/tmp/brutehunter/report/ip/risk_ip.txt）"
  cat risk_ip.txt
}

# 登录最早时间线溯源Time_ip():
function Time_ip(){
  ip=$(cat $dir/risk_ip.txt)
  echo "
------------------------------------------------------------------------------------------------------------------------------------
日志记录信息："
  for line in $ip
  do
    grep $line /var/log/*secure*|echo "$f" >> $dir/$line.txt
    grep $line /var/log/*auth* >> $dir/$line.txt
    who|grep $line >> $dir/$line.txt
    #grep $line /var/log/audit/*audi* >> $dir/$line.txt >/dev/null 2>&1
    last|grep $line >> $dir/$line.txt
  done
}

# 登录操作行为分析
#function Action_ip(){
#}

mkfile
Flogin_ip
Slogin_ip
Combine_ip
Time_ip


