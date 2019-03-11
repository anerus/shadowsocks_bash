
#! /usr/bin/env bash
PATH="/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin"
export PATH

#ss脚本作者
#托管：https://github.com/uxh/shadowsocks_bash
#作者：https://www.banwagongzw.com & https://www.vultrcn.com
#致谢：https://teddysun.com
#=================================================
#	mtproxy脚本作者
#	System Required: CentOS/Debian/Ubuntu
#	Description: MTProxy Golang
#	Version: 1.0.1
#	Author: Toyo
#	Blog: https://doub.io/shell-jc9/
#=================================================

#设置输出颜色
red="\033[0;31m"
green="\033[0;32m"
yellow="\033[0;33m"
plain="\033[0m"

#获取当前目录
currentdir=$(pwd)

#设置加密方式数组
ciphers=(
aes-256-gcm
aes-128-gcm
aes-256-ctr
aes-256-cfb
chacha20-ietf-poly1305
chacha20-ietf
chacha20
rc4-md5
)

#环境及程序版本控制
libsodiumver="libsodium-1.0.17"
libsodiumurl="https://github.com/jedisct1/libsodium/releases/download/1.0.17/libsodium-1.0.17.tar.gz"
mbedtlsver="mbedtls-2.16.0"
mbedtlsurl="https://tls.mbed.org/download/mbedtls-2.16.0-gpl.tgz"
shadowsocksver="shadowsocks-libev-3.2.4"
shadowsocksurl="https://github.com/shadowsocks/shadowsocks-libev/releases/download/v3.2.4/shadowsocks-libev-3.2.4.tar.gz"
initscripturl="https://raw.githubusercontent.com/uxh/shadowsocks_bash/master/shadowsocks-libev"

#禁用 SElinux
function disable_selinux() {
    if [ -s /etc/selinux/config ] && grep "SELINUX=enforcing" /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

#检查当前系统类型
function check_release() {
    local value=$1
    local release="none"

    if [ -f /etc/redhat-release ]; then
        release="centos"
    elif grep -qi "centos|red hat|redhat" /etc/issue; then
        release="centos"
    elif grep -qi "debian|raspbian" /etc/issue; then
        release="debian"
    elif grep -qi "ubuntu" /etc/issue; then
        release="ubuntu"
    elif grep -qi "centos|red hat|redhat" /proc/version; then
        release="centos"
    elif grep -qi "debian" /proc/version; then
        release="debian"
    elif grep -qi "ubuntu" /proc/version; then
        release="ubuntu"
    elif grep -qi "centos|red hat|redhat" /etc/*-release; then
        release="centos"
    elif grep -qi "debian" /etc/*-release; then
        release="debian"
    elif grep -qi "ubuntu" /etc/*-release; then
        release="ubuntu"
    fi

    if [[ ${value} == ${release} ]]; then
        return 0
    else
        return 1
    fi
}

#检查 Shadowsocks 状态
function check_shadowsocks_status() {
    installedornot="not"
    runningornot="not"
    updateornot="not"
    command -v ss-server > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        installedornot="installed"
        ps -ef | grep -v "grep" | grep "ss-server" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            runningornot="running"
        fi
        local installedversion=$(ss-server -h | grep "shadowsocks-libev" | cut -d " " -f 2)
        local latestversion=$(echo "$(wget --no-check-certificate -qO- https://api.github.com/repos/shadowsocks/shadowsocks-libev/releases/latest | grep "tag_name" | cut -d "\"" -f 4)" | sed -e 's/^[a-zA-Z]//g')
        if [ ! -z ${latestversion} ]; then
            if [[ ${installedversion} != ${latestversion} ]]; then
                updateornot="update"
                shadowsocksnewver="shadowsocks-libev-${latestversion}"
                shadowsocksnewurl="https://github.com/shadowsocks/shadowsocks-libev/releases/download/v${latestversion}/${shadowsocksnewver}.tar.gz"
            fi
        fi
    fi
}

#检查 CentOS 系统大版本
function check_centos_main_version() {
    local value=$1
    local version="0.0.0"

    if [ -s /etc/redhat-release ]; then
        version=$(grep -Eo "[0-9.]+" /etc/redhat-release)
    else
        version=$(grep -Eo "[0-9.]+" /etc/issue)
    fi

    local mainversion=${version%%.*}

    if [ ${value} -eq ${mainversion} ]; then
        return 0
    else
        return 1
    fi
}

#检查当前系统内核一
function check_kernel_version() {
    local kernelversion=$(uname -r | cut -d "-" -f 1)
    local olderversion=$(echo "${kernelversion} 3.7.0" | tr " " "\n" | sort -V | head -n 1)
    if [[ ${olderversion} == "3.7.0" ]]; then
        return 0
    else
        return 1
    fi
}

#检查当前系统内核二
function check_kernel_headers() {
    local nowkernel=$(uname -r)
    if check_release centos; then
        rpm -qa | grep "headers-${nowkernel}" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            return 0
        else
            return 1
        fi
    else
        dpkg -s linux-headers-${nowkernel} > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            return 0
        else
            return 1
        fi
    fi
}

#获取系统公网 IPv4
function get_ipv4() {
    local ipv4=$(ip addr | grep -Eo "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | grep -Ev "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1)
    if [ -z ${ipv4} ]; then
        ipv4=$(wget -qO- -t 1 -T 10 ipv4.icanhazip.com)
    fi
    if [ -z ${ipv4} ]; then
        ipv4=$(wget -qO- -t 1 -T 10 ipinfo.io/ip)
    fi
    echo -e "${ipv4}"
}

#检查系统公网 IPv6
function check_ipv6() {
    local ipv6=$(wget -qO- -t 1 -T 10 ipv6.icanhazip.com)
    if [ -z ${ipv6} ]; then
        return 1
    else
        return 0
    fi
}

#设置 Shadowsocks 连接信息
function set_shadowsocks_config() {
    clear
    echo -e "${green}[提示]${plain} 开始配置 Shadowsocks 连接信息"
    echo -e "${green}[提示]${plain} 不清楚的地方，直接回车采用默认配置即可"
    echo ""
    echo "请设置 Shadowsocks 的连接密码"
    read -p "[默认为 Number1433223]：" sspassword
    if [ -z ${sspassword} ]; then
        sspassword="Number1433223"
    fi
    echo "-------------------------------"
    echo "连接密码已设置为：${sspassword}"
    echo "-------------------------------"

    local defaultport=$(shuf -i 9000-9999 -n 1)
    echo "请设置 Shadowsocks 连接端口（1~65535）"
    while true
    do
        read -p "[默认为 ${defaultport}]：" ssport
        if [ -z ${ssport} ]; then
            ssport=${defaultport}
        fi
        expr ${ssport} + 1 > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            if [ ${ssport} -ge 1 ] && [ ${ssport} -le 65535 ]; then
                echo "-------------------------------"
                echo "连接端口已设置为：${ssport}"
                echo "-------------------------------"
                break
            else
                echo -e "${red}[错误]${plain} 请输入 1 和 65535 之间的数字！"
            fi
        else
            echo -e "${red}[错误]${plain} 请输入 1 和 65535 之间的数字！"
        fi
    done

    echo "请设置 Shadowsocks 的加密方式"
    for ((i=1;i<=${#ciphers[@]};i++));
    do
        local cipher=${ciphers[$i-1]}
        echo -e "${i}) ${cipher}"
    done
    while true
    do
        read -p "[默认为 ${ciphers[0]}]：" ciphernumber
        if [ -z ${ciphernumber} ]; then
            ciphernumber="1"
        fi
        expr ${ciphernumber} + 1 > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            if [ ${ciphernumber} -ge 1 ] && [ ${ciphernumber} -le ${#ciphers[@]} ]; then
                sscipher=${ciphers[${ciphernumber}-1]}
                echo "-------------------------------"
                echo "加密方式已设置为：${sscipher}"
                echo "-------------------------------"
                break
            else
                echo -e "${red}[错误]${plain} 请输入 1 和 ${#ciphers[@]} 之间的数字！"
            fi
        else
            echo -e "${red}[错误]${plain} 请输入 1 和 ${#ciphers[@]} 之间的数字！"
        fi
    done

    echo ""
    echo "按回车键开始安装...或按 Ctrl+C 键取消"
    read -n 1
}

#安装依赖
function install_dependencies() {
    if check_release centos; then
        if [ ! -f /etc/yum.repos.d/epel.repo ]; then
            yum install -y epel-release
            if [ $? -ne 0 ]; then
                echo -e "${red}[错误]${plain} EPEL 更新源安装失败，请稍后重试！"
                exit 1
            fi
        fi
        command -v yum-config-manager > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            yum install -y yum-utils
        fi
        local epelstatus=$(yum-config-manager epel | grep -w "enabled" | cut -d " " -f 3)
        if [[ ${epelstatus} != "True" ]]; then
            yum-config-manager --enable epel
        fi
        yum install -y unzip openssl openssl-devel gettext gcc autoconf libtool automake make asciidoc xmlto libev-devel pcre pcre-devel git c-ares-devel
        if [ $? -ne 0 ]; then
            echo -e "${red}[错误]${plain} 依赖安装失败，请稍后重试！"
            exit 1
        fi
    else
        apt-get update
        apt-get install --no-install-recommends -y gettext build-essential autoconf automake libtool openssl libssl-dev zlib1g-dev libpcre3-dev libev-dev libc-ares-dev
        if [ $? -ne 0 ]; then
            echo -e "${red}[错误]${plain} 依赖安装失败，请稍后重试！"
            exit 1
        fi
    fi
    echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" > /etc/resolv.conf
}

#设置防火墙
function set_firewall() {
    if check_release centos; then
        if check_centos_main_version 6; then
            /etc/init.d/iptables status > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                iptables -L -n | grep "${ssport}" > /dev/null 2>&1
                if [ $? -ne 0 ]; then
                    iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssport} -j ACCEPT
                    iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssport} -j ACCEPT
                    /etc/init.d/iptables save
                    /etc/init.d/iptables restart
                fi
            fi
        elif check_centos_main_version 7; then
            systemctl status firewalld > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                firewall-cmd --query-port=${ssport}/tcp > /dev/null 2>&1
                if [ $? -ne 0 ]; then
                    local default_zone=$(firewall-cmd --get-default-zone)
                    firewall-cmd --permanent --zone=${default_zone} --add-port=${ssport}/tcp
                    firewall-cmd --permanent --zone=${default_zone} --add-port=${ssport}/udp
                    firewall-cmd --reload
                fi
            fi
        fi
    fi
}

#下载函数
function download() {
    local filename=$1

    if [ -s ${filename} ]; then
        echo -e "${green}[提示]${plain} ${filename} 已下载"
    else
        echo -e "${green}[提示]${plain} ${filename} 未找到，开始下载"
        wget --no-check-certificate -c -t 3 -T 60 -O $1 $2
        if [ $? -eq 0 ]; then
            echo -e "${green}[提示]${plain} ${filename} 下载完成"
        else
            echo -e "${red}[错误]${plain} ${filename} 下载失败，请稍后重试！"
            exit 1
        fi
    fi
}

#安装libsodium
function install_libsodium() {
    cd ${currentdir}
    if [ ! -f /usr/lib/libsodium.a ]; then
        download "${libsodiumver}.tar.gz" "${libsodiumurl}"
        tar zxf ${libsodiumver}.tar.gz
        cd ${libsodiumver}
        ./configure --prefix=/usr && make && make install
        if [ $? -ne 0 ]; then
            echo -e "${red}[错误]${plain} ${libsodiumver} 安装失败，请稍后重试！"
            exit 1
        fi
    else
        echo -e "${green}[提示]${plain} ${libsodiumver} 已安装"
    fi

    cd ${currentdir}
    rm -rf ${libsodiumver} ${libsodiumver}.tar.gz
}

#安装mbedtls
function install_mbedtls() {
    cd ${currentdir}
    if [ ! -f /usr/lib/libmbedtls.a ]; then
        download "${mbedtlsver}-gpl.tgz" "${mbedtlsurl}"
        tar xf ${mbedtlsver}-gpl.tgz
        cd ${mbedtlsver}
        make SHARED=1 CFLAGS=-fPIC
        make DESTDIR=/usr install
        if [ $? -ne 0 ]; then
            echo -e "${red}[错误]${plain} ${mbedtlsver} 安装失败，请稍后重试！"
            exit 1
        fi
    else
        echo -e "${green}[提示]${plain} ${mbedtlsver} 已安装"
    fi

    cd ${currentdir}
    rm -rf ${mbedtlsver} ${mbedtlsver}-gpl.tgz
}

#创建shadowsocks配置文件
function config_shadowsocks() {
    if check_ipv6; then
        server_value="[\"[::0]\",\"0.0.0.0\"]"
    else
        server_value="\"0.0.0.0\""
    fi

    if check_kernel_version && check_kernel_headers; then
        fast_open="true"
    else
        fast_open="false"
    fi

    if [ ! -d /etc/shadowsocks-libev ]; then
        mkdir -p /etc/shadowsocks-libev
    fi

    cat > /etc/shadowsocks-libev/config.json << EOF
{
    "server":${server_value},
    "server_port":${ssport},
    "password":"${sspassword}",
    "timeout":300,
    "user":"nobody",
    "method":"${sscipher}",
    "fast_open":${fast_open},
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp"
}
EOF
}

#安装shadowsocks
function install_shadowsocks() {
    ldconfig
    cd ${currentdir}
    if [[ ${updateornot} == "not" ]]; then
        download "${shadowsocksver}.tar.gz" "${shadowsocksurl}"
        tar zxf ${shadowsocksver}.tar.gz
        cd ${shadowsocksver}
    else
        download "${shadowsocksnewver}.tar.gz" "${shadowsocksnewurl}"
        tar zxf ${shadowsocksnewver}.tar.gz
        cd ${shadowsocksnewver}
    fi
    ./configure --disable-documentation
    make && make install
    if [ $? -ne 0 ]; then
        echo -e "${red}[错误]${plain} Shadowsocks 安装失败，请稍后重试！"
        exit 1
    fi
    if [ ! -f /etc/init.d/shadowsocks ]; then
        download "/etc/init.d/shadowsocks" "${initscripturl}"
    fi
    chmod +x /etc/init.d/shadowsocks
    /etc/init.d/shadowsocks start
    if [ $? -ne 0 ]; then
        echo -e "${red}[错误]${plain} Shadowsocks 启动失败，请稍后重试！"
        exit 1
    fi
    if check_release centos; then
        chkconfig --add shadowsocks
        chkconfig shadowsocks on
    else
        update-rc.d -f shadowsocks defaults
    fi

    cd ${currentdir}
    if [[ ${updateornot} == "not" ]]; then
        rm -rf ${shadowsocksver} ${shadowsocksver}.tar.gz
    else
        rm -rf ${shadowsocksnewver} ${shadowsocksnewver}.tar.gz
    fi
}

#卸载shadowsocks
function uninstall_shadowsocks() {
    ps -ef | grep -v "grep" | grep "ss-server" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        /etc/init.d/shadowsocks stop
    fi
    if check_release centos; then
        chkconfig --del shadowsocks
    else
        update-rc.d -f shadowsocks remove
    fi
    rm -rf /etc/shadowsocks-libev
    rm -f /usr/local/bin/ss-local
    rm -f /usr/local/bin/ss-tunnel
    rm -f /usr/local/bin/ss-server
    rm -f /usr/local/bin/ss-manager
    rm -f /usr/local/bin/ss-redir
    rm -f /usr/local/bin/ss-nat
    rm -f /usr/local/lib/libshadowsocks-libev.a
    rm -f /usr/local/lib/libshadowsocks-libev.la
    rm -f /usr/local/include/shadowsocks.h
    rm -f /usr/local/lib/pkgconfig/shadowsocks-libev.pc
    rm -f /usr/local/share/man/man1/ss-local.1
    rm -f /usr/local/share/man/man1/ss-tunnel.1
    rm -f /usr/local/share/man/man1/ss-server.1
    rm -f /usr/local/share/man/man1/ss-manager.1
    rm -f /usr/local/share/man/man1/ss-redir.1
    rm -f /usr/local/share/man/man1/ss-nat.1
    rm -f /usr/local/share/man/man8/shadowsocks-libev.8
    rm -rf /usr/local/share/doc/shadowsocks-libev
    rm -f /etc/init.d/shadowsocks
    rm -f /root/shadowsocks.txt
}

#安装完成信息
function install_success() {
    local ssurl=$(echo -n "${sscipher}:${sspassword}@$(get_ipv4):${ssport}" | base64 -w0)
    clear
    echo -e "${green}[提示]${plain} Shadowsocks 安装成功，配置信息为"
    echo -e "==============================================="
    echo -e "服务器地址  : \033[41;37m $(get_ipv4) \033[0m"
    echo -e "服务端口    : \033[41;37m ${ssport} \033[0m"
    echo -e "连接密码    : \033[41;37m ${sspassword} \033[0m"
    echo -e "加密方式    : \033[41;37m ${sscipher} \033[0m"
    echo -e "-----------------------------------------------"
    echo -e "ss://${ssurl}"
    echo -e "==============================================="

    cat > /root/shadowsocks.txt << EOF
===============================================
服务器地址  : $(get_ipv4)
服务端口    : ${ssport}
连接密码    : ${sspassword}
加密方式    : ${sscipher}
-----------------------------------------------
ss://${ssurl}
===============================================
EOF
    echo -e "配置信息已备份在 /root/shadowsocks.txt 文件内"
    echo ""
    echo -e "搬瓦工中文网（https://www.banwagongzw.com）、VULTR中文网（https://www.vultrcn.com）"
    echo -e "站内教程多多，欢迎访问！"
}

#功能部分一
install_main() {
    disable_selinux
    set_shadowsocks_config
    install_dependencies
    set_firewall
    install_libsodium
    install_mbedtls
    config_shadowsocks
    install_shadowsocks
    install_success
}

#功能部分二
uninstall_main() {
    uninstall_shadowsocks
    echo -e "${green}[提示]${plain} Shadowsocks 已成功卸载"
}

#功能部分三
update_main() {
    if [[ ${updateornot} == "update" ]]; then
        ps -ef | grep -v grep | grep -i "ss-server" > /dev/null 2>&1
        [ $? -eq 0 ] && /etc/init.d/shadowsocks stop
        install_shadowsocks
        echo -e "${green}[提示]${plain} Shadowsocks 更新成功"
    else
        echo -e "${green}[提示]${plain} Shadowsocks 已安装最新版，无需更新"
    fi
}

#功能部分四
start_main() {
    /etc/init.d/shadowsocks start
    if [ $? -eq 0 ]; then
        echo -e "${green}[提示]${plain} Shadowsocks 启动成功"
    else
        echo -e "${red}[错误]${plain} Shadowsocks 启动失败，请稍后重试！"
    fi
}

#功能部分五
stop_main() {
    /etc/init.d/shadowsocks stop
    if [ $? -eq 0 ]; then
        echo -e "${green}[提示]${plain} Shadowsocks 停止成功"
    else
        echo -e "${red}[错误]${plain} Shadowsocks 停止失败，请稍后重试！"
    fi
}

#功能部分六
restart_main() {
    /etc/init.d/shadowsocks stop
    /etc/init.d/shadowsocks start
    if [ $? -eq 0 ]; then
        echo -e "${green}[提示]${plain} Shadowsocks 重启成功"
    else
        echo -e "${red}[错误]${plain} Shadowsocks 重启失败，请稍后重试！"
    fi
}

#功能部分七
status_main() {
    echo -e "${green}[提示]${plain} 当前 Shadowsocks 配置信息为"
    cat /root/shadowsocks.txt
    echo "此信息仅供参考，具体请查看 Shadowsocks 配置文件"
}

#功能部分八
modify_main() {
    set_shadowsocks_config
    /etc/init.d/shadowsocks stop
    set_firewall
    config_shadowsocks
    /etc/init.d/shadowsocks start
    install_success
    echo ""
    echo "若修改后无法生效，请尝试重启解决！"
}
#mtproxy部分
sh_ver="1.0.1"
filepath=$(cd "$(dirname "$0")"; pwd)
file_1=$(echo -e "${filepath}"|awk -F "$0" '{print $1}')
file="/usr/local/mtproxy-go"
mtproxy_file="/usr/local/mtproxy-go/mtg"
mtproxy_conf="/usr/local/mtproxy-go/mtproxy.conf"
mtproxy_log="/usr/local/mtproxy-go/mtproxy.log"
Now_ver_File="/usr/local/mtproxy-go/ver.txt"
Crontab_file="/usr/bin/crontab"

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Green_font_prefix}[注意]${Font_color_suffix}"

check_root(){
	[[ $EUID != 0 ]] && echo -e "${Error} 当前非ROOT账号(或没有ROOT权限)，无法继续操作，请更换ROOT账号或使用 ${Green_background_prefix}sudo su${Font_color_suffix} 命令获取临时ROOT权限（执行后可能会提示输入当前账号的密码）。" && exit 1
}
#检查系统
check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
	bit=`uname -m`
}
check_installed_status(){
	[[ ! -e ${mtproxy_file} ]] && echo -e "${Error} MTProxy 没有安装，请检查 !" && exit 1
}
check_crontab_installed_status(){
	if [[ ! -e ${Crontab_file} ]]; then
		echo -e "${Error} Crontab 没有安装，开始安装..."
		if [[ ${release} == "centos" ]]; then
			yum install crond -y
		else
			apt-get install cron -y
		fi
		if [[ ! -e ${Crontab_file} ]]; then
			echo -e "${Error} Crontab 安装失败，请检查！" && exit 1
		else
			echo -e "${Info} Crontab 安装成功！"
		fi
	fi
}
check_pid(){
	PID=$(ps -ef| grep "./mtg "| grep -v "grep" | grep -v "init.d" |grep -v "service" |awk '{print $2}')
}
check_new_ver(){
	new_ver=$(wget -qO- https://api.github.com/repos/9seconds/mtg/releases| grep "tag_name"| head -n 1| awk -F ":" '{print $2}'| sed 's/\"//g;s/,//g;s/ //g')
	[[ -z ${new_ver} ]] && echo -e "${Error} MTProxy 最新版本获取失败！" && exit 1
	echo -e "${Info} 检测到 MTProxy 最新版本为 [ ${new_ver} ]"
}
check_ver_comparison(){
	now_ver=$(cat ${Now_ver_File})
	if [[ "${now_ver}" != "${new_ver}" ]]; then
		echo -e "${Info} 发现 MTProxy 已有新版本 [ ${new_ver} ]，旧版本 [ ${now_ver} ]"
		read -e -p "是否更新 ? [Y/n] :" yn
		[[ -z "${yn}" ]] && yn="y"
		if [[ $yn == [Yy] ]]; then
			check_pid
			[[ ! -z $PID ]] && kill -9 ${PID}
			\cp "${mtproxy_conf}" "/tmp/mtproxy.conf"
			rm -rf ${file}
			Download
			mv "/tmp/mtproxy.conf" "${mtproxy_conf}"
			Start
		fi
	else
		echo -e "${Info} 当前 MTProxy 已是最新版本 [ ${new_ver} ]" && exit 1
	fi
}
Download(){
	if [[ ! -e "${file}" ]]; then
		mkdir "${file}"
	else
		[[ -e "${mtproxy_file}" ]] && rm -rf "${mtproxy_file}"
	fi
	cd "${file}"
	if [[ ${bit} == "x86_64" ]]; then
		bit="amd64"
	elif [[ ${bit} == "i386" || ${bit} == "i686" ]]; then
		bit="386"
	else
		bit="arm"
	fi
	wget --no-check-certificate -N "https://github.com/9seconds/mtg/releases/download/${new_ver}/mtg-linux-${bit}"
	[[ ! -e "mtg-linux-${bit}" ]] && echo -e "${Error} MTProxy 下载失败 !" && rm -rf "${file}" && exit 1
	mv "mtg-linux-${bit}" "mtg"
	[[ ! -e "mtg" ]] && echo -e "${Error} MTProxy 重命名失败 !" && rm -rf "${file}" && exit 1
	chmod +x mtg
	echo "${new_ver}" > ${Now_ver_File}
}
Service(){
	if [[ ${release} = "centos" ]]; then
		if ! wget --no-check-certificate "https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/service/mtproxy_go_centos" -O /etc/init.d/mtproxy-go; then
			echo -e "${Error} MTProxy服务 管理脚本下载失败 !"
			rm -rf "${file}"
			exit 1
		fi
		chmod +x "/etc/init.d/mtproxy-go"
		chkconfig --add mtproxy-go
		chkconfig mtproxy-go on
	else
		if ! wget --no-check-certificate "https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/service/mtproxy_go_debian" -O /etc/init.d/mtproxy-go; then
			echo -e "${Error} MTProxy服务 管理脚本下载失败 !"
			rm -rf "${file}"
			exit 1
		fi
		chmod +x "/etc/init.d/mtproxy-go"
		update-rc.d -f mtproxy-go defaults
	fi
	echo -e "${Info} MTProxy服务 管理脚本下载完成 !"
}
Installation_dependency(){
	\cp -f /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
}
Write_config(){
	cat > ${mtproxy_conf}<<-EOF
PORT = ${mtp_port}
PASSWORD = ${mtp_passwd}
TAG = ${mtp_tag}
NAT-IPv4 = ${mtp_nat_ipv4}
NAT-IPv6 = ${mtp_nat_ipv6}
SECURE = ${mtp_secure}
EOF
}
Read_config(){
	[[ ! -e ${mtproxy_conf} ]] && echo -e "${Error} MTProxy 配置文件不存在 !" && exit 1
	port=$(cat ${mtproxy_conf}|grep 'PORT = '|awk -F 'PORT = ' '{print $NF}')
	passwd=$(cat ${mtproxy_conf}|grep 'PASSWORD = '|awk -F 'PASSWORD = ' '{print $NF}')
	tag=$(cat ${mtproxy_conf}|grep 'TAG = '|awk -F 'TAG = ' '{print $NF}')
	nat_ipv4=$(cat ${mtproxy_conf}|grep 'NAT-IPv4 = '|awk -F 'NAT-IPv4 = ' '{print $NF}')
	nat_ipv6=$(cat ${mtproxy_conf}|grep 'NAT-IPv6 = '|awk -F 'NAT-IPv6 = ' '{print $NF}')
	secure=$(cat ${mtproxy_conf}|grep 'SECURE = '|awk -F 'SECURE = ' '{print $NF}')
}
Set_port(){
	while true
		do
		echo -e "请输入 MTProxy 端口 [1-65535]"
		read -e -p "(默认: 443):" mtp_port
		[[ -z "${mtp_port}" ]] && mtp_port="443"
		echo $((${mtp_port}+0)) &>/dev/null
		if [[ $? -eq 0 ]]; then
			if [[ ${mtp_port} -ge 1 ]] && [[ ${mtp_port} -le 65535 ]]; then
				echo && echo "========================"
				echo -e "	端口 : ${Red_background_prefix} ${mtp_port} ${Font_color_suffix}"
				echo "========================" && echo
				break
			else
				echo "输入错误, 请输入正确的端口。"
			fi
		else
			echo "输入错误, 请输入正确的端口。"
		fi
		done
}
Set_passwd(){
	while true
		do
		echo "请输入 MTProxy 密匙（手动输入必须为32位，[0-9][a-z][A-Z]，建议随机生成）"
		read -e -p "(避免出错，强烈推荐随机生成，直接回车):" mtp_passwd
		if [[ -z "${mtp_passwd}" ]]; then
			mtp_passwd=$(date +%s%N | md5sum | head -c 32)
		else
			[[ ${#mtp_passwd} != 32 ]] && echo -e "${Error} 请输入正确的密匙（32位字符）。" && continue
		fi
		echo && echo "========================"
		echo -e "	密码 : ${Red_background_prefix} dd${mtp_passwd} ${Font_color_suffix}"
		echo "========================" && echo
		break
	done
}
Set_tag(){
	echo "请输入 MTProxy 的 TAG标签（TAG标签必须是32位，TAG标签只有在通过官方机器人 @MTProxybot 分享代理账号后才会获得，不清楚请留空回车）"
	read -e -p "(默认：回车跳过):" mtp_tag
	if [[ ! -z "${mtp_tag}" ]]; then
		echo && echo "========================"
		echo -e "	TAG : ${Red_background_prefix} ${mtp_tag} ${Font_color_suffix}"
		echo "========================" && echo
	else
		echo
	fi
}
Set_nat(){
	echo -e "如果本机是NAT服务器（谷歌云、微软云、阿里云等，网卡绑定的IP为 10.xx.xx.xx 开头的），则需要指定公网 IPv4。"
	read -e -p "(默认：自动检测 IPv4 地址):" mtp_nat_ipv4
	if [[ -z "${mtp_nat_ipv4}" ]]; then
		getipv4
		if [[ "${ipv4}" == "IPv4_Error" ]]; then
			mtp_nat_ipv4=""
		else
			mtp_nat_ipv4="${ipv4}"
		fi
		echo && echo "========================"
		echo -e "	NAT-IPv4 : ${Red_background_prefix} ${mtp_nat_ipv4} ${Font_color_suffix}"
		echo "========================" && echo
	fi
	echo -e "如果本机是NAT服务器（谷歌云、微软云、阿里云等），则需要指定公网 IPv6。"
	read -e -p "(默认：自动检测 IPv6 地址):" mtp_nat_ipv6
	if [[ -z "${mtp_nat_ipv6}" ]]; then
		getipv6
		if [[ "${ipv6}" == "IPv6_Error" ]]; then
			mtp_nat_ipv6=""
		else
			mtp_nat_ipv6="${ipv6}"
		fi
		echo && echo "========================"
		echo -e "	NAT-IPv6 : ${Red_background_prefix} ${mtp_nat_ipv6} ${Font_color_suffix}"
		echo "========================" && echo
	fi
}
Set_secure(){
	echo -e "是否启用强制安全模式？[Y/n]
只有启用[安全混淆模式]的客户端才能链接(即密匙头部有 dd 字符)，降低服务器被墙几率，建议开启。"
	read -e -p "(默认：Y 启用):" mtp_secure
	[[ -z "${mtp_secure}" ]] && mtp_secure="Y"
	if [[ "${mtp_secure}" == [Yy] ]]; then
		mtp_secure="YES"
	else
		mtp_secure="NO"
	fi
	echo && echo "========================"
	echo -e "	强制安全模式 : ${Red_background_prefix} ${mtp_secure} ${Font_color_suffix}"
	echo "========================" && echo
}
Set(){
	check_installed_status
	echo && echo -e "你要做什么？
 ${Green_font_prefix}1.${Font_color_suffix}  修改 端口配置
 ${Green_font_prefix}2.${Font_color_suffix}  修改 密码配置
 ${Green_font_prefix}3.${Font_color_suffix}  修改 TAG 配置
 ${Green_font_prefix}4.${Font_color_suffix}  修改 NAT 配置
 ${Green_font_prefix}5.${Font_color_suffix}  修改 强制安全模式 配置
 ${Green_font_prefix}6.${Font_color_suffix}  修改 全部配置
————————————————
 ${Green_font_prefix}7.${Font_color_suffix}  监控 运行状态
 ${Green_font_prefix}8.${Font_color_suffix}  监控 外网IP变更" && echo
	read -e -p "(默认: 取消):" mtp_modify
	[[ -z "${mtp_modify}" ]] && echo "已取消..." && exit 1
	if [[ "${mtp_modify}" == "1" ]]; then
		Read_config
		Set_port
		mtp_passwd=${passwd}
		mtp_tag=${tag}
		mtp_nat_ipv4=${nat_ipv4}
		mtp_nat_ipv6=${nat_ipv6}
		mtp_secure=${secure}
		Write_config
		Del_iptables
		Add_iptables
		Restart
	elif [[ "${mtp_modify}" == "2" ]]; then
		Read_config
		Set_passwd
		mtp_port=${port}
		mtp_tag=${tag}
		mtp_nat_ipv4=${nat_ipv4}
		mtp_nat_ipv6=${nat_ipv6}
		mtp_secure=${secure}
		Write_config
		Restart
	elif [[ "${mtp_modify}" == "3" ]]; then
		Read_config
		Set_tag
		mtp_port=${port}
		mtp_passwd=${passwd}
		mtp_nat_ipv4=${nat_ipv4}
		mtp_nat_ipv6=${nat_ipv6}
		mtp_secure=${secure}
		Write_config
		Restart
	elif [[ "${mtp_modify}" == "4" ]]; then
		Read_config
		Set_nat
		mtp_port=${port}
		mtp_passwd=${passwd}
		mtp_tag=${tag}
		mtp_secure=${secure}
		Write_config
		Restart
	elif [[ "${mtp_modify}" == "5" ]]; then
		Read_config
		Set_secure
		mtp_port=${port}
		mtp_passwd=${passwd}
		mtp_tag=${tag}
		mtp_nat_ipv4=${nat_ipv4}
		mtp_nat_ipv6=${nat_ipv6}
		Write_config
		Restart
	elif [[ "${mtp_modify}" == "6" ]]; then
		Read_config
		Set_port
		Set_passwd
		Set_tag
		Set_nat
		Set_secure
		Write_config
		Restart
	elif [[ "${mtp_modify}" == "7" ]]; then
		Set_crontab_monitor
	elif [[ "${mtp_modify}" == "8" ]]; then
		Set_crontab_monitorip
	else
		echo -e "${Error} 请输入正确的数字(1-8)" && exit 1
	fi
}
Install(){
	check_root
	[[ -e ${mtproxy_file} ]] && echo -e "${Error} 检测到 MTProxy 已安装 !" && exit 1
	echo -e "${Info} 开始设置 用户配置..."
	Set_port
	Set_passwd
	Set_tag
	Set_nat
	Set_secure
	echo -e "${Info} 开始安装/配置 依赖..."
	Installation_dependency
	echo -e "${Info} 开始下载/安装..."
	check_new_ver
	Download
	echo -e "${Info} 开始下载/安装 服务脚本(init)..."
	Service
	echo -e "${Info} 开始写入 配置文件..."
	Write_config
	echo -e "${Info} 开始设置 iptables防火墙..."
	Set_iptables
	echo -e "${Info} 开始添加 iptables防火墙规则..."
	Add_iptables
	echo -e "${Info} 开始保存 iptables防火墙规则..."
	Save_iptables
	echo -e "${Info} 所有步骤 安装完毕，开始启动..."
	Start
}
Start(){
	check_installed_status
	check_pid
	[[ ! -z ${PID} ]] && echo -e "${Error} MTProxy 正在运行，请检查 !" && exit 1
	/etc/init.d/mtproxy-go start
	sleep 1s
	check_pid
	[[ ! -z ${PID} ]] && View
}
Stop(){
	check_installed_status
	check_pid
	[[ -z ${PID} ]] && echo -e "${Error} MTProxy 没有运行，请检查 !" && exit 1
	/etc/init.d/mtproxy-go stop
}
Restart(){
	check_installed_status
	check_pid
	[[ ! -z ${PID} ]] && /etc/init.d/mtproxy-go stop
	/etc/init.d/mtproxy-go start
	sleep 1s
	check_pid
	[[ ! -z ${PID} ]] && View
}
Update(){
	check_installed_status
	check_new_ver
	check_ver_comparison
}
Uninstall(){
	check_installed_status
	echo "确定要卸载 MTProxy ? (y/N)"
	echo
	read -e -p "(默认: n):" unyn
	[[ -z ${unyn} ]] && unyn="n"
	if [[ ${unyn} == [Yy] ]]; then
		check_pid
		[[ ! -z $PID ]] && kill -9 ${PID}
		if [[ -e ${mtproxy_conf} ]]; then
			port=$(cat ${mtproxy_conf}|grep 'PORT = '|awk -F 'PORT = ' '{print $NF}')
			Del_iptables
			Save_iptables
		fi
		if [[ ! -z $(crontab -l | grep "mtproxy_go.sh monitor") ]]; then
			crontab_monitor_cron_stop
		fi
		rm -rf "${file}"
		if [[ ${release} = "centos" ]]; then
			chkconfig --del mtproxy-go
		else
			update-rc.d -f mtproxy-go remove
		fi
		rm -rf "/etc/init.d/mtproxy-go"
		echo && echo "MTProxy 卸载完成 !" && echo
	else
		echo && echo "卸载已取消..." && echo
	fi
}
getipv4(){
	ipv4=$(wget -qO- -4 -t1 -T2 ipinfo.io/ip)
	if [[ -z "${ipv4}" ]]; then
		ipv4=$(wget -qO- -4 -t1 -T2 api.ip.sb/ip)
		if [[ -z "${ipv4}" ]]; then
			ipv4=$(wget -qO- -4 -t1 -T2 members.3322.org/dyndns/getip)
			if [[ -z "${ipv4}" ]]; then
				ipv4="IPv4_Error"
			fi
		fi
	fi
}
getipv6(){
	ipv6=$(wget -qO- -6 -t1 -T3 ifconfig.co)
	if [[ -z "${ipv6}" ]]; then
		ipv6="IPv6_Error"
	fi
}
View(){
	check_installed_status
	Read_config
	#getipv4
	#getipv6
	clear && echo
	echo -e "Mtproto Proxy 用户配置："
	echo -e "————————————————"
	echo -e " 地址\t: ${Green_font_prefix}${nat_ipv4}${Font_color_suffix}"
	[[ ! -z "${nat_ipv6}" ]] && echo -e " 地址\t: ${Green_font_prefix}${nat_ipv6}${Font_color_suffix}"
	echo -e " 端口\t: ${Green_font_prefix}${port}${Font_color_suffix}"
	echo -e " 密匙\t: ${Green_font_prefix}dd${passwd}${Font_color_suffix}"
	[[ ! -z "${tag}" ]] && echo -e " TAG \t: ${Green_font_prefix}${tag}${Font_color_suffix}"
	echo -e " 链接\t: ${Red_font_prefix}tg://proxy?server=${nat_ipv4}&port=${port}&secret=dd${passwd}${Font_color_suffix}"
	echo -e " 链接\t: ${Red_font_prefix}https://t.me/proxy?server=${nat_ipv4}&port=${port}&secret=dd${passwd}${Font_color_suffix}"
	[[ ! -z "${nat_ipv6}" ]] && echo -e " 链接\t: ${Red_font_prefix}tg://proxy?server=${nat_ipv6}&port=${port}&secret=dd${passwd}${Font_color_suffix}"
	[[ ! -z "${nat_ipv6}" ]] && echo -e " 链接\t: ${Red_font_prefix}https://t.me/proxy?server=${nat_ipv6}&port=${port}&secret=dd${passwd}${Font_color_suffix}"
	echo
	echo -e " 强制安全模式\t: ${Green_font_prefix}${secure}${Font_color_suffix}"
	echo
	echo -e " ${Red_font_prefix}注意\t:${Font_color_suffix} 密匙头部的 ${Green_font_prefix}dd${Font_color_suffix} 字符是代表客户端启用${Green_font_prefix}安全混淆模式${Font_color_suffix}，可以降低服务器被墙几率。\n     \t  另外，在官方机器人处分享账号获取TAG标签时记得删除，获取TAG标签后分享时可以再加上。"
}
View_Log(){
	check_installed_status
	[[ ! -e ${mtproxy_log} ]] && echo -e "${Error} MTProxy 日志文件不存在 !" && exit 1
	echo && echo -e "${Tip} 按 ${Red_font_prefix}Ctrl+C${Font_color_suffix} 终止查看日志" && echo -e "如果需要查看完整日志内容，请用 ${Red_font_prefix}cat ${mtproxy_log}${Font_color_suffix} 命令。" && echo
	tail -f ${mtproxy_log}
}
# 显示 连接信息
debian_View_user_connection_info(){
	format_1=$1
	Read_config
	user_IP=$(ss state connected sport = :${port} -tn|sed '1d'|awk '{print $NF}'|awk -F ':' '{print $(NF-1)}'|sort -u)
	if [[ -z ${user_IP} ]]; then
		user_IP_total="0"
		echo -e "端口: ${Green_font_prefix}"${port}"${Font_color_suffix}\t 链接IP总数: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t 当前链接IP: "
	else
		user_IP_total=$(echo -e "${user_IP}"|wc -l)
		if [[ ${format_1} == "IP_address" ]]; then
			echo -e "端口: ${Green_font_prefix}"${port}"${Font_color_suffix}\t 链接IP总数: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t 当前链接IP: "
			get_IP_address
			echo
		else
			user_IP=$(echo -e "\n${user_IP}")
			echo -e "端口: ${Green_font_prefix}"${user_port}"${Font_color_suffix}\t 链接IP总数: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t 当前链接IP: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
		fi
	fi
	user_IP=""
}
View_user_connection_info(){
	check_installed_status
	echo && echo -e "请选择要显示的格式：
 ${Green_font_prefix}1.${Font_color_suffix} 显示 IP 格式
 ${Green_font_prefix}2.${Font_color_suffix} 显示 IP+IP归属地 格式" && echo
	read -e -p "(默认: 1):" mtproxy_connection_info
	[[ -z "${mtproxy_connection_info}" ]] && mtproxy_connection_info="1"
	if [[ "${mtproxy_connection_info}" == "1" ]]; then
		View_user_connection_info_1 ""
	elif [[ "${mtproxy_connection_info}" == "2" ]]; then
		echo -e "${Tip} 检测IP归属地(ipip.net)，如果IP较多，可能时间会比较长..."
		View_user_connection_info_1 "IP_address"
	else
		echo -e "${Error} 请输入正确的数字(1-2)" && exit 1
	fi
}
View_user_connection_info_1(){
	format=$1
	debian_View_user_connection_info "$format"
}
get_IP_address(){
	if [[ ! -z ${user_IP} ]]; then
		for((integer_1 = ${user_IP_total}; integer_1 >= 1; integer_1--))
		do
			IP=$(echo "${user_IP}" |sed -n "$integer_1"p)
			IP_address=$(wget -qO- -t1 -T2 http://freeapi.ipip.net/${IP}|sed 's/\"//g;s/,//g;s/\[//g;s/\]//g')
			echo -e "${Green_font_prefix}${IP}${Font_color_suffix} (${IP_address})"
			sleep 1s
		done
	fi
}
Set_crontab_monitor(){
	check_crontab_installed_status
	crontab_monitor_status=$(crontab -l|grep "mtproxy_go.sh monitor")
	if [[ -z "${crontab_monitor_status}" ]]; then
		echo && echo -e "当前监控运行状态模式: ${Red_font_prefix}未开启${Font_color_suffix}" && echo
		echo -e "确定要开启 ${Green_font_prefix}MTProxy 服务端运行状态监控${Font_color_suffix} 功能吗？(当进程关闭则自动启动 MTProxy 服务端)[Y/n]"
		read -e -p "(默认: y):" crontab_monitor_status_ny
		[[ -z "${crontab_monitor_status_ny}" ]] && crontab_monitor_status_ny="y"
		if [[ ${crontab_monitor_status_ny} == [Yy] ]]; then
			crontab_monitor_cron_start
		else
			echo && echo "	已取消..." && echo
		fi
	else
		echo && echo -e "当前监控运行状态模式: ${Green_font_prefix}已开启${Font_color_suffix}" && echo
		echo -e "确定要关闭 ${Red_font_prefix}MTProxy 服务端运行状态监控${Font_color_suffix} 功能吗？(当进程关闭则自动启动 MTProxy 服务端)[y/N]"
		read -e -p "(默认: n):" crontab_monitor_status_ny
		[[ -z "${crontab_monitor_status_ny}" ]] && crontab_monitor_status_ny="n"
		if [[ ${crontab_monitor_status_ny} == [Yy] ]]; then
			crontab_monitor_cron_stop
		else
			echo && echo "	已取消..." && echo
		fi
	fi
}
crontab_monitor_cron_start(){
	crontab -l > "$file_1/crontab.bak"
	sed -i "/mtproxy_go.sh monitor/d" "$file_1/crontab.bak"
	echo -e "\n* * * * * /bin/bash $file_1/mtproxy_go.sh monitor" >> "$file_1/crontab.bak"
	crontab "$file_1/crontab.bak"
	rm -r "$file_1/crontab.bak"
	cron_config=$(crontab -l | grep "mtproxy_go.sh monitor")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} MTProxy 服务端运行状态监控功能 启动失败 !" && exit 1
	else
		echo -e "${Info} MTProxy 服务端运行状态监控功能 启动成功 !"
	fi
}
crontab_monitor_cron_stop(){
	crontab -l > "$file_1/crontab.bak"
	sed -i "/mtproxy_go.sh monitor/d" "$file_1/crontab.bak"
	crontab "$file_1/crontab.bak"
	rm -r "$file_1/crontab.bak"
	cron_config=$(crontab -l | grep "mtproxy_go.sh monitor")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} MTProxy 服务端运行状态监控功能 停止失败 !" && exit 1
	else
		echo -e "${Info} MTProxy 服务端运行状态监控功能 停止成功 !"
	fi
}
crontab_monitor(){
	check_installed_status
	check_pid
	#echo "${PID}"
	if [[ -z ${PID} ]]; then
		echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] 检测到 MTProxy服务端 未运行 , 开始启动..." | tee -a ${mtproxy_log}
		/etc/init.d/mtproxy-go start
		sleep 1s
		check_pid
		if [[ -z ${PID} ]]; then
			echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] MTProxy服务端 启动失败..." | tee -a ${mtproxy_log}
		else
			echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] MTProxy服务端 启动成功..." | tee -a ${mtproxy_log}
		fi
	else
		echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] MTProxy服务端 进程运行正常..." | tee -a ${mtproxy_log}
	fi
}
Set_crontab_monitorip(){
	check_crontab_installed_status
	crontab_monitor_status=$(crontab -l|grep "mtproxy_go.sh monitorip")
	if [[ -z "${crontab_monitor_status}" ]]; then
		echo && echo -e "当前监控外网IP模式: ${Red_font_prefix}未开启${Font_color_suffix}" && echo
		echo -e "确定要开启 ${Green_font_prefix}服务器外网IP变更监控${Font_color_suffix} 功能吗？(当服务器外网IP变化后，自动重新配置并重启服务端)[Y/n]"
		read -e -p "(默认: y):" crontab_monitor_status_ny
		[[ -z "${crontab_monitor_status_ny}" ]] && crontab_monitor_status_ny="y"
		if [[ ${crontab_monitor_status_ny} == [Yy] ]]; then
			crontab_monitor_cron_start2
		else
			echo && echo "	已取消..." && echo
		fi
	else
		echo && echo -e "当前监控外网IP模式: ${Green_font_prefix}已开启${Font_color_suffix}" && echo
		echo -e "确定要关闭 ${Red_font_prefix}服务器外网IP变更监控${Font_color_suffix} 功能吗？(当服务器外网IP变化后，自动重新配置并重启服务端)[Y/n]"
		read -e -p "(默认: n):" crontab_monitor_status_ny
		[[ -z "${crontab_monitor_status_ny}" ]] && crontab_monitor_status_ny="n"
		if [[ ${crontab_monitor_status_ny} == [Yy] ]]; then
			crontab_monitor_cron_stop2
		else
			echo && echo "	已取消..." && echo
		fi
	fi
}
crontab_monitor_cron_start2(){
	crontab -l > "$file_1/crontab.bak"
	sed -i "/mtproxy_go.sh monitorip/d" "$file_1/crontab.bak"
	echo -e "\n* * * * * /bin/bash $file_1/mtproxy_go.sh monitorip" >> "$file_1/crontab.bak"
	crontab "$file_1/crontab.bak"
	rm -r "$file_1/crontab.bak"
	cron_config=$(crontab -l | grep "mtproxy_go.sh monitorip")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} 服务器外网IP变更监控功能 启动失败 !" && exit 1
	else
		echo -e "${Info} 服务器外网IP变更监控功能 启动成功 !"
	fi
}
crontab_monitor_cron_stop2(){
	crontab -l > "$file_1/crontab.bak"
	sed -i "/mtproxy_go.sh monitorip/d" "$file_1/crontab.bak"
	crontab "$file_1/crontab.bak"
	rm -r "$file_1/crontab.bak"
	cron_config=$(crontab -l | grep "mtproxy_go.sh monitorip")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} 服务器外网IP变更监控功能 停止失败 !" && exit 1
	else
		echo -e "${Info} 服务器外网IP变更监控功能 停止成功 !"
	fi
}
crontab_monitorip(){
	check_installed_status
	Read_config
	getipv4
	getipv6
	monitorip_yn="NO"
	if [[ "${ipv4}" != "IPv4_Error" ]]; then
		if [[ "${ipv4}" != "${nat_ipv4}" ]]; then
			echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] 检测到 服务器外网IPv4变更[旧: ${nat_ipv4}，新: ${ipv4}], 开始重新配置并准备重启服务端..." | tee -a ${mtproxy_log}
			monitorip_yn="YES"
			mtp_nat_ipv4=${ipv4}
		fi
	else
		echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] 服务器外网IPv4获取失败..." | tee -a ${mtproxy_log}
		mtp_nat_ipv4=${nat_ipv4}
	fi
	if [[ "${ipv6}" != "IPv6_Error" ]]; then
		if [[ "${ipv6}" != "${nat_ipv6}" ]]; then
			echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] 检测到 服务器外网IPv6变更[旧: ${nat_ipv6}，新: ${ipv6}], 开始重新配置并准备重启服务端..." | tee -a ${mtproxy_log}
			monitorip_yn="YES"
			mtp_nat_ipv6=${ipv6}
		fi
	else
		echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] 服务器外网IPv6获取失败..." | tee -a ${mtproxy_log}
		mtp_nat_ipv6=${nat_ipv6}
	fi
	if [[ ${monitorip_yn} == "YES" ]]; then
		mtp_port=${port}
		mtp_passwd=${passwd}
		mtp_tag=${tag}
		mtp_secure=${secure}
		Write_config
		Restart
	fi
}
Add_iptables(){
	iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${mtp_port} -j ACCEPT
	ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${mtp_port} -j ACCEPT
}
Del_iptables(){
	iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
	ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
}
Save_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
	fi
}
Set_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
		chkconfig --level 2345 iptables on
		chkconfig --level 2345 ip6tables on
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
		echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules\n/sbin/ip6tables-restore < /etc/ip6tables.up.rules' > /etc/network/if-pre-up.d/iptables
		chmod +x /etc/network/if-pre-up.d/iptables
	fi
}
Update_Shell(){
	sh_new_ver=$(wget --no-check-certificate -qO- -t1 -T3 "https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/mtproxy_go.sh"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1) && sh_new_type="github"
	[[ -z ${sh_new_ver} ]] && echo -e "${Error} 无法链接到 Github !" && exit 0
	if [[ -e "/etc/init.d/mtproxy-go" ]]; then
		rm -rf /etc/init.d/mtproxy-go
		Service
	fi
	wget -N --no-check-certificate "https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/mtproxy_go.sh" && chmod +x mtproxy_go.sh
	echo -e "脚本已更新为最新版本[ ${sh_new_ver} ] !(注意：因为更新方式为直接覆盖当前运行的脚本，所以可能下面会提示一些报错，无视即可)" && exit 0
}
#起始部分
if [ $EUID -eq 0 ]; then
    if check_release centos || check_release debian || check_release ubuntu; then
        clear
        echo "=================================="
        echo " Shadowsocks 一键管理脚本（libev）"
        echo "=================================="
        echo " 1.安装 Shadowsocks 服务"
        echo " 2.卸载 Shadowsocks 服务"
        echo " 3.更新 Shadowsocks 服务"
        echo "----------------------------------"
        echo " 4.启动 Shadowsocks 服务"
        echo " 5.停止 Shadowsocks 服务"
        echo " 6.重启 Shadowsocks 服务"
        echo "----------------------------------"
        echo " 7.查看 Shadowsocks 配置"
        echo " 8.修改 Shadowsocks 配置"
        echo "=================================="
		echo " mtproxy 一键管理脚本（go）"
		echo "=================================="
		echo " 9.安装 MTProxy"
		echo "10.更新 MTProxy"
		echo "11.卸载 MTProxy"
		echo "----------------------------------"
		echo "12.启动 MTProxy"
		echo "13.停止 MTProxy"
		echo "14.重启 MTProxy"
		echo "----------------------------------"
		echo "15.设置 账号配置"
		echo "16.查看 账号信息"
		echo "17.查看 日志信息"
		echo "18.查看 链接信息"
		echo "=================================="
        echo "shadowsocks状态"
		check_shadowsocks_status
        if [[ ${installedornot} == "installed" ]]; then
            if [[ ${runningornot} == "running" ]]; then
                if [[ ${updateornot} == "not" ]]; then
                    echo -e "${green}已安装且正在运行${plain}"
                else
                    echo -e "${green}已安装且正在运行，版本可更新${plain}"
                fi
            else
                echo -e "${yellow}已安装但未运行${plain}"
            fi
        else
            echo -e "${red}尚未安装${plain}"
        fi
		echo "=================================="
		echo "mtproxy 状态"
		if [[ -e ${mtproxy_file} ]]; then
			check_pid
			if [[ ! -z "${PID}" ]]; then
				echo -e " 当前状态: ${Green_font_prefix}已安装${Font_color_suffix} 并 ${Green_font_prefix}已启动${Font_color_suffix}"
			else
				echo -e " 当前状态: ${Green_font_prefix}已安装${Font_color_suffix} 但 ${Red_font_prefix}未启动${Font_color_suffix}"
			fi
		else
			echo -e " 当前状态: ${Red_font_prefix}未安装${Font_color_suffix}"
		fi

        while true
        do
            echo ""
            read -p "请输入相应功能前面的数字：" choice
            [[ -z ${choice} ]] && choice="0"
            expr ${choice} + 1 > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                if [ ${choice} -ge 1 ] && [ ${choice} -le 18 ]; then
                    if [ "${choice}" == "1" ]; then
                        install_main
                    elif [ "${choice}" == "2" ]; then
                        uninstall_main
                    elif [ "${choice}" == "3" ]; then
                        update_main
                    elif [ "${choice}" == "4" ]; then
                        start_main
                    elif [ "${choice}" == "5" ]; then
                        stop_main
                    elif [ "${choice}" == "6" ]; then
                        restart_main
                    elif [ "${choice}" == "7" ]; then
                        status_main
                    elif [ "${choice}" == "8" ]; then
                        modify_main
                    elif [ "${choice}" == "9" ]; then
                        Install
                    elif [ "${choice}" == "10" ]; then
                        Update
                    elif [ "${choice}" == "11" ]; then
                        Uninstall
                    elif [ "${choice}" == "12" ]; then
                        Start
                    elif [ "${choice}" == "13" ]; then
                        Stop
                    elif [ "${choice}" == "14" ]; then
                        Restart
                    elif [ "${choice}" == "15" ]; then
                        Set
                    elif [ "${choice}" == "16" ]; then
                        View
                    elif [ "${choice}" == "17" ]; then
                        View_Log
                    elif [ "${choice}" == "18" ]; then
                        View_user_connection_info						
                    fi
                    break
                else
                    echo -e "${red}[错误]${plain} 请输入 1 和 18 之间的数字！"
                fi
            else
                echo -e "${red}[错误]${plain} 请输入 1 和 18 之间的数字！"
            fi
        done
    else
        echo -e "${red}[错误]${plain} 本脚本只支持 CentOS、Debian 及 Ubuntu 系统！"
        exit 1
    fi
else
    echo -e "${red}[错误]${plain} 请以 root 用户身份运行此脚本！"
    exit 1
fi
