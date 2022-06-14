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

web_domain=$1
trojan_passwd=${TROJAN_PASSWD:?Please Set TROJAN_PASSWD Before Run This Script}

help() {
    blue "Usage: TROJAN_PASSWD=<YOUR PASSWORD> $0 [web domain name]"
}

if [ -z "$web_domain" ]; then
    help
    exit 1
fi

# shellcheck source=/dev/null
source /etc/os-release
RELEASE=$ID
if [ "$RELEASE" == "centos" ]; then
    release="centos"
    instTool="yum"
elif [ "$RELEASE" == "debian" ] || [ "$RELEASE" == "ubuntu" ]; then
    release="debian"
    instTool="apt-get"
else
    red "Not Support This Platform"
    exit 1
fi

function install_nginx() {
    $instTool install -y nginx
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
        server_name  $web_domain;
        root /usr/share/nginx/html;
        index index.php index.html index.htm;
    }
}
EOF
    systemctl enable nginx
    systemctl start nginx
}

function install_fake_site() {
    systemctl stop nginx
    rm -rf /usr/share/nginx/html/*
    cd /usr/share/nginx/html/ || exit 1
    wget https://github.com/xcnix/trojan/raw/master/fakesite.zip >/dev/null 2>&1
    unzip fakesite.zip >/dev/null 2>&1
    rm -rf fakesite.zip
    sleep 5
    systemctl start nginx
}
 
function install_http_cert() {
    curl https://get.acme.sh | sh
    # latest acme tool will use zerossl by default
    ~/.acme.sh/acme.sh  --set-default-ca --server letsencrypt
    ~/.acme.sh/acme.sh  --register-account  -m admin@"$web_domain" --server letsencrypt
    # Test before apply
    if ~/.acme.sh/acme.sh --issue -d "$web_domain" --nginx --staging; then
        rm -rf ~/.acme.sh/*.cer
        rm -rf ~/.acme.sh/*.key
        ~/.acme.sh/acme.sh  --issue  -d "$web_domain"  --nginx 
    fi

    if [ ! -f ~/.acme.sh/"$web_domain"/fullchain.cer ]; then
       red "ERROR: Apply Cert Failed" 
       exit 1
    fi

    ~/.acme.sh/acme.sh  --install-cert  -d  "$web_domain"   \
    --key-file   /usr/src/trojan-cert/"$web_domain"/private.key \
    --fullchain-file  /usr/src/trojan-cert/"$web_domain"/fullchain.cer

    ~/.acme.sh/acme.sh --upgrade --auto-upgrade
}

function check_cert_expire() {
    if [ -f ~/.acme.sh/"$web_domain"/fullchain.cer ]; then
        cert_expire_date=$(openssl x509 -in ~/.acme.sh/"$web_domain"/fullchain.cer -noout -enddate | cut -d= -f2)
        cert_expire_date_timestamp=$(date -d "$cert_expire_date" +%s)
        now_timestamp=$(date +%s)
        if [ $((cert_expire_date_timestamp - now_timestamp)) -le 0 ]; then
            red "ERROR: Cert Expire"
            exit 1
        fi
    fi
}

function install_trojan_cert() {
    if [ ! -d "/usr/src/trojan-cert/" ]; then
        mkdir -p /usr/src/trojan-cert/
    fi

    cp -r ~/.acme.sh/"$web_domain" /usr/src/trojan-cert/

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
        server_name  $web_domain;
        root /usr/share/nginx/html;
        index index.php index.html index.htm;
    }
    server {
        listen       0.0.0.0:80;
        server_name  $web_domain;
        return 301 https://$web_domain\$request_uri;
    }
    
}
EOF
}

function install_trojan(){
    cd /usr/src || exit 1
    wget https://api.github.com/repos/trojan-gfw/trojan/releases/latest >/dev/null 2>&1
    latest_version=$(grep tag_name latest | awk -F '[:,"v]' '{print $6}')
    rm -f latest
    green "Start to downloading latesting trojan amd64"
    wget https://github.com/trojan-gfw/trojan/releases/download/v"${latest_version}"/trojan-"${latest_version}"-linux-amd64.tar.xz
    tar xf trojan-"${latest_version}"-linux-amd64.tar.xz >/dev/null 2>&1
    rm -f trojan-"${latest_version}"-linux-amd64.tar.xz
  
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
        "cert": "/usr/src/trojan-cert/$web_domain/fullchain.cer",
        "key": "/usr/src/trojan-cert/$web_domain/private.key",
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
}

function install_trojan_service() {
    cat > /etc/systemd/system/trojan.service <<-EOF
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
    systemctl enable trojan.service
}

function preinstall_check(){
    nginx_status=$(pgrep "nginx: worker" |grep -v "grep")
    if [ -n "$nginx_status" ]; then
        systemctl stop nginx
    fi
    $instTool -y install net-tools socat >/dev/null 2>&1
    Port80=$(netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 80)
    Port443=$(netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 443)
    if [ -n "$Port80" ]; then
        red "Port 80 is in Use, Please Check and Run this Script Again"
        exit 1
    fi
    if [ -n "$Port443" ]; then
        red "Port 443 is in Use, Please Check and Run this Script Again"
        exit 1
    fi

    # Disable selinux on CentOS
    if [ -f "/etc/selinux/config" ]; then
            setenforce 0
            sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
            sed -i 's/SELINUX=permissive/SELINUX=disabled/g' /etc/selinux/config
    fi

    if [ "$release" == "centos" ]; then
        if ! systemctl is-active firewalld >/dev/null 2>&1; then
            firewall-cmd --zone=public --add-port=80/tcp --permanent
            firewall-cmd --zone=public --add-port=443/tcp --permanent
            firewall-cmd --reload
        fi
    fi

    if [[ "$release" == "debian" ]]; then
        if ! systemctl is-active ufw >/dev/null 2>&1; then
            ufw allow 80/tcp
            ufw allow 443/tcp
            ufw reload
        fi
    fi

    $instTool -y install wget unzip zip curl tar >/dev/null 2>&1
    real_addr=$(ping "${web_domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
    local_addr=$(curl ipv4.icanhazip.com)
    if [ "$real_addr" == "$local_addr" ] ; then
        green "Starting to Install Trojan"
        install_trojan
    else
        red "ERROR: IP Binded to Web Domain Name is not Match with Local IP"
        exit 1
    fi
}

function repair_cert(){
    systemctl stop nginx
    Port80=$(netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 80)
    if [ -n "$Port80" ]; then
        red "Port 80 is Still in Use, Please Close the Port firstly"
        exit 1
    fi

    real_addr=$(ping "${web_domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
    local_addr=$(curl ipv4.icanhazip.com)
    if [ "$real_addr" == "$local_addr" ] ; then
        ~/.acme.sh/acme.sh  --issue  -d "$web_domain"  --standalone
        ~/.acme.sh/acme.sh  --installcert  -d  "$web_domain"   \
            --key-file   /usr/src/trojan-cert/"$web_domain"/private.key \
            --fullchain-file /usr/src/trojan-cert/"$web_domain"/fullchain.cer \
            --reloadcmd  "systemctl restart trojan"
        if test -s /usr/src/trojan-cert/"$web_domain"/fullchain.cer; then
            green "Apply Http Cert Successfully"
            systemctl restart trojan
            systemctl start nginx
        else
            red "Failed to Apply Http Cert"
        fi
    else
        red "IP Binded to Domain Not Match Local IP"
        red "Please Check DNS Setting of Web Domain Name"
    fi
}

function remove_trojan(){
    red "--- Starting to Uninstall Trojan & Nginx---"
    systemctl stop trojan
    systemctl disable trojan
    systemctl stop nginx
    systemctl disable nginx
    rm -f /etc/systemd/system/trojan.service
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
        green "Current Trojan is up-to-date!"
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
