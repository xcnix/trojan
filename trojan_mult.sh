#!/bin/bash

# Original Script From: https://github.com/atrandys/trojan

function blue(){
    echo -e "\033[34m\033[01m$1\033[0m"
}

function green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}

function red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}

function version_lt(){
    test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" != "$1"; 
}

# shellcheck source=/dev/null
source /etc/os-release
RELEASE=$ID
if [ "$RELEASE" == "centos" ]; then
    release="centos"
    systemPackage="yum"
elif [ "$RELEASE" == "debian" ]; then
    release="debian"
    systemPackage="apt-get"
elif [ "$RELEASE" == "ubuntu" ]; then
    release="ubuntu"
    systemPackage="apt-get"
fi
systempwd="/etc/systemd/system/"

function install_trojan(){
    $systemPackage install -y nginx
    if [ ! -d "/etc/nginx/" ]; then
        red "nginx home is not exist, please unintall trojan then reinstall"
        exit 1
    fi
    cat > /etc/nginx/nginx.conf <<-EOF
user  root;
worker_processes  1;
error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;
events {
    worker_connections  1024;
}
http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';
    access_log  /var/log/nginx/access.log  main;
    sendfile        on;
    #tcp_nopush     on;
    keepalive_timeout  120;
    client_max_body_size 20m;
    #gzip  on;
    server {
        listen       80;
        server_name  $your_domain;
        root /usr/share/nginx/html;
        index index.php index.html index.htm;
    }
}
EOF
    systemctl restart nginx
    sleep 3
    rm -rf /usr/share/nginx/html/*
    cd /usr/share/nginx/html/ || exit 1
    wget https://github.com/xcnix/trojan/raw/master/fakesite.zip >/dev/null 2>&1
    unzip fakesite.zip >/dev/null 2>&1
    sleep 5
    if [ ! -d "/usr/src" ]; then
        mkdir /usr/src
    fi
    if [ ! -d "/usr/src/trojan-cert" ]; then
        mkdir /usr/src/trojan-cert /usr/src/trojan-temp
        mkdir /usr/src/trojan-cert/"$your_domain"
        if [ ! -d "/usr/src/trojan-cert/$your_domain" ]; then
            red "/usr/src/trojan-cert/$your_domain is not exist"
            exit 1
        fi
        curl https://get.acme.sh | sh
        # latest acme tool will use zerossl by default
        ~/.acme.sh/acme.sh  --set-default-ca --server letsencrypt
        ~/.acme.sh/acme.sh  --issue  -d "$your_domain"  --nginx
        if test -s /root/.acme.sh/"$your_domain"/fullchain.cer; then
            cert_success="1"
        fi
    elif [ -f "/usr/src/trojan-cert/$your_domain/fullchain.cer" ]; then
        cd /usr/src/trojan-cert/"$your_domain" || exit 1
        create_time=$(stat -c %Y fullchain.cer)
        now_time=$(date +%s)
        minus=$((now_time - create_time ))
        if [  $minus -gt 5184000 ]; then
            curl https://get.acme.sh | sh
            ~/.acme.sh/acme.sh  --issue  -d "$your_domain"  --nginx
            if test -s /root/.acme.sh/"$your_domain"/fullchain.cer; then
                cert_success="1"
            fi
        else 
            green "Cert of domain: $your_domain is valid"
            cert_success="1"
        fi        
    else 
        mkdir /usr/src/trojan-cert/"$your_domain"
        curl https://get.acme.sh | sh
        ~/.acme.sh/acme.sh  --issue  -d "$your_domain"  --nginx
        if test -s /root/.acme.sh/"$your_domain"/fullchain.cer; then
            cert_success="1"
        fi
    fi
    
    if [ "$cert_success" == "1" ]; then
        cat > /etc/nginx/nginx.conf <<-EOF
user  root;
worker_processes  1;
error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;
events {
    worker_connections  1024;
}
http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';
    access_log  /var/log/nginx/access.log  main;
    sendfile        on;
    #tcp_nopush     on;
    keepalive_timeout  120;
    client_max_body_size 20m;
    #gzip  on;
    server {
        listen       127.0.0.1:80;
        server_name  $your_domain;
        root /usr/share/nginx/html;
        index index.php index.html index.htm;
    }
    server {
        listen       0.0.0.0:80;
        server_name  $your_domain;
        return 301 https://$your_domain\$request_uri;
    }
    
}
EOF
        systemctl restart nginx
        systemctl enable nginx
        cd /usr/src || exit 1
        wget https://api.github.com/repos/trojan-gfw/trojan/releases/latest >/dev/null 2>&1
        latest_version=$(grep tag_name latest| awk -F '[:,"v]' '{print $6}')
        rm -f latest
        green "Start to downloading latesting trojan amd64"
        wget https://github.com/trojan-gfw/trojan/releases/download/v"${latest_version}"/trojan-"${latest_version}"-linux-amd64.tar.xz
        tar xf trojan-"${latest_version}"-linux-amd64.tar.xz >/dev/null 2>&1
        rm -f trojan-"${latest_version}"-linux-amd64.tar.xz

        green "Please set password for trojan:"
        read -r -p "Input trojan password :" trojan_passwd
        rm -rf /usr/src/trojan/server.conf
        cat > /usr/src/trojan/server.conf <<-EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        "$trojan_passwd"
    ],
    "log_level": 1,
    "ssl": {
        "cert": "/usr/src/trojan-cert/$your_domain/fullchain.cer",
        "key": "/usr/src/trojan-cert/$your_domain/private.key",
        "key_password": "",
        "cipher_tls13":"TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        "prefer_server_cipher": true,
        "alpn": [
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": false,
        "session_timeout": 600,
        "plain_http_response": "",
        "curves": "",
        "dhparam": ""
    },
    "tcp": {
        "no_delay": true,
        "keep_alive": true,
        "fast_open": false,
        "fast_open_qlen": 20
    },
    "mysql": {
        "enabled": false,
        "server_addr": "127.0.0.1",
        "server_port": 3306,
        "database": "trojan",
        "username": "trojan",
        "password": ""
    }
}
EOF
        rm -rf /usr/src/trojan-temp/

        cat > ${systempwd}trojan.service <<-EOF
[Unit]  
Description=trojan  
After=network.target  
   
[Service]  
Type=simple  
PIDFile=/usr/src/trojan/trojan/trojan.pid
ExecStart=/usr/src/trojan/trojan -c "/usr/src/trojan/server.conf"  
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=1s
   
[Install]  
WantedBy=multi-user.target
EOF
        chmod +x ${systempwd}trojan.service
        systemctl enable trojan.service
        cd /root || exit 1
        ~/.acme.sh/acme.sh  --installcert  -d  "$your_domain"   \
            --key-file   /usr/src/trojan-cert/"$your_domain"/private.key \
            --fullchain-file  /usr/src/trojan-cert/"$your_domain"/fullchain.cer \
            --reloadcmd  "systemctl restart trojan"	
    else
        red "==================================="
        red "Installed Failed due to Http Cert Error"
        red "==================================="
    fi
}

function preinstall_check(){
    nginx_status=$(pgrep "nginx: worker" |grep -v "grep")
    if [ -n "$nginx_status" ]; then
        systemctl stop nginx
    fi
    $systemPackage -y install net-tools socat >/dev/null 2>&1
    Port80=$(netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 80)
    Port443=$(netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 443)
    if [ -n "$Port80" ]; then
        red "==========================================================="
        red "80 Port is in Use, Please Check and Run this Script Again"
        red "==========================================================="
        exit 1
    fi
    if [ -n "$Port443" ]; then
        red "============================================================="
        red "443 Port is in Use, Please Check and Run this Script Again"
        red "============================================================="
        exit 1
    fi

    # Disable selinux on CentOS
    if [ -f "/etc/selinux/config" ]; then
            setenforce 0
            sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
            sed -i 's/SELINUX=permissive/SELINUX=disabled/g' /etc/selinux/config
    fi

    if [ "$release" == "centos" ]; then
        firewall_status=$(systemctl status firewalld | grep "Active: active")
        if [ -n "$firewall_status" ]; then
            green "Firewalld is Active, Add Rules to Allow 80/443 Ports"
            firewall-cmd --zone=public --add-port=80/tcp --permanent
            firewall-cmd --zone=public --add-port=443/tcp --permanent
            firewall-cmd --reload
        fi
    fi

    if [ "$release" == "ubuntu" ]; then
        ufw_status=$(systemctl status ufw | grep "Active: active")
        if [ -n "$ufw_status" ]; then
            ufw allow 80/tcp
            ufw allow 443/tcp
            ufw reload
        fi
        apt-get update
    elif [ "$release" == "debian" ]; then
        ufw_status=$(systemctl status ufw | grep "Active: active")
        if [ -n "$ufw_status" ]; then
            ufw allow 80/tcp
            ufw allow 443/tcp
            ufw reload
        fi
        apt-get update
    fi

    $systemPackage -y install  wget unzip zip curl tar >/dev/null 2>&1
    green "======================="
    blue "Please Input Your Domain Name:"
    green "======================="
    read -r your_domain
    real_addr=$(ping "${your_domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
    local_addr=$(curl ipv4.icanhazip.com)
    if [ "$real_addr" == "$local_addr" ] ; then
        green "=========================================="
        green "       Successful to Resolve Your Domain Name. "
        green "       Starting to Install Trojan"
        green "=========================================="
        sleep 1
        install_trojan
    else
        red "===================================="
        red "IP Binded to Your Domain Name is not Match with Local IP"
        red "Do you want to Continue?[y/n]"
        red "===================================="
        read -r -p "Force Continue ? Please Input [Y/n] :" yn
        [ -z "${yn}" ] && yn="y"
        if [[ $yn == [Yy] ]]; then
            green "Force Continue ..."
            sleep 1
            install_trojan
        else
            exit 1
        fi
    fi
}

function repair_cert(){
    systemctl stop nginx
    Port80=$(netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 80)
    if [ -n "$Port80" ]; then
        red "==========================================================="
        red "80 Port is Still in Use, Please Close the Port 80 firstly"
        red "==========================================================="
        exit 1
    fi
    green "============================"
    blue "Please Enter the Domain Name Same as Before"
    green "============================"
    read -r your_domain
    real_addr=$(ping "${your_domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
    local_addr=$(curl ipv4.icanhazip.com)
    if [ "$real_addr" == "$local_addr" ] ; then
        ~/.acme.sh/acme.sh  --issue  -d "$your_domain"  --standalone
        ~/.acme.sh/acme.sh  --installcert  -d  "$your_domain"   \
            --key-file   /usr/src/trojan-cert/"$your_domain"/private.key \
            --fullchain-file /usr/src/trojan-cert/"$your_domain"/fullchain.cer \
            --reloadcmd  "systemctl restart trojan"
        if test -s /usr/src/trojan-cert/"$your_domain"/fullchain.cer; then
            green "Apply Http Cert Successfully"
            systemctl restart trojan
            systemctl start nginx
        else
            red "Failed to Apply Http Cert"
        fi
    else
        red "================================"
        red "IP Binded to Domain Not Match Local IP"
        red "Please Check DNS Setting of Your Domain Name"
        red "================================"
    fi
}

function remove_trojan(){
    red "================================"
    red "Starting to Uninstall Trojan"
    red "and Will Uninstall Nginx at the same time"
    red "================================"
    systemctl stop trojan
    systemctl disable trojan
    systemctl stop nginx
    systemctl disable nginx
    rm -f ${systempwd}trojan.service
    if [ "$release" == "centos" ]; then
        yum remove -y nginx
    else
        apt-get -y autoremove nginx
        apt-get -y --purge remove nginx
        apt-get -y autoremove && apt-get -y autoclean
        find / | grep nginx | sudo xargs rm -rf
    fi
    rm -rf /usr/src/trojan/
    rm -rf /usr/src/trojan-cli/
    rm -rf /usr/share/nginx/html/*
    rm -rf /etc/nginx/
    rm -rf /root/.acme.sh/
    green "=============="
    green "trojan has been deleted."
    green "=============="
}

function update_trojan(){
    /usr/src/trojan/trojan -v 2>trojan.tmp
    curr_version=$(grep "trojan" trojan.tmp | awk '{print $4}')
    wget https://api.github.com/repos/trojan-gfw/trojan/releases/latest >/dev/null 2>&1
    latest_version=$(grep tag_name latest| awk -F '[:,"v]' '{print $6}')
    rm -f latest
    rm -f trojan.tmp
    if version_lt "$curr_version" "$latest_version"; then
        green "Upgrading Current Trojan: $curr_version to Latest Version: $latest_version ......"
        mkdir trojan_update_temp && cd trojan_update_temp || exit 1
        wget https://github.com/trojan-gfw/trojan/releases/download/v"${latest_version}"/trojan-"${latest_version}"-linux-amd64.tar.xz >/dev/null 2>&1
        tar xf trojan-"${latest_version}"-linux-amd64.tar.xz >/dev/null 2>&1
        mv ./trojan/trojan /usr/src/trojan/
        cd .. && rm -rf trojan_update_temp
        systemctl restart trojan
    /usr/src/trojan/trojan -v 2>trojan.tmp
    green "Upgrade Trojan Completed. Please download latest client manually."
    rm -f trojan.tmp
    else
        green "Currenty trojan is up-to-date!"
    fi
}

start_menu(){
    clear
    echo
    green "1. Install Trojan"
    green "2. Uninstall Trojan"
    green "3. Upgrade Trojan"
    green "4. Repair Http Cert"
    green "0. Quit"
    echo
    read -r -p "Pleae Input Number :" num
    case "$num" in
    1)
    preinstall_check
    ;;
    2)
    remove_trojan 
    ;;
    3)
    update_trojan 
    ;;
    4)
    repair_cert 
    ;;
    0)
    exit 1
    ;;
    *)
    clear
    red "Please Input Corrent Number (1,2,3,4 or 0)"
    sleep 1
    start_menu
    ;;
    esac
}

start_menu
