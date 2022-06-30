#!/usr/bin/env bash

# https://trojan-tutor.github.io/2019/04/10/p41.html

web_domain=$1

sudo apt update
sudo apt upgrade -y
# deps for acme.sh
sudo apt install -y socat cron curl
# deps for trojan
sudo apt install -y libcap2-bin xz-utils nano

sudo apt install -y nginx

sudo systemctl enable --now nginx

cat <<EOF > /etc/nginx/nginx.conf
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
        listen       []::]:80;
        server_name  $web_domain;
        return 301 https://$web_domain\$request_uri;
    }
    
}
EOF

cat <<EOF > /etc/nginx/sites-available/$web_domain
server {
    listen 127.0.0.1:80 default_server;

    server_name <tdom.ml>;

    location / {
        proxy_pass https://www.ietf.org;
    }

}

server {
    listen 127.0.0.1:80;

    server_name $web_domain;

    return 301 https://$web_domain$request_uri;
}

server {
    listen 0.0.0.0:80;
    listen [::]:80;

    server_name _;

    location / {
        return 301 https://$host$request_uri;
    }

    location /.well-known/acme-challenge {
       root /var/www/acme-challenge;
    }
}
EOF
