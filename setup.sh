#!/bin/bash
########gotdeb.com#########github.com/eunas/gotdeb##########
############################################################
# Core
############################################################
check_install() {
        if [ $(dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -c "ok installed") -eq $2 ]
        then
    if [ -n "$3" ]; then
        print_warn "$3"
    fi
    if [ -n "$4" ]; then
        version=$(dpkg -s $1 | grep 'Version')
        print_info "$version"
    fi
        exit 1
        fi
}
print_info() { echo "$(tput bold)$(tput setaf 3)$*$(tput sgr0)"; }
print_warn() { echo "$(tput bold)$(tput setaf 1)$*$(tput sgr0)"; }
print_done() { echo "$(tput bold)$(tput setaf 2)$*$(tput sgr0)"; }
die() { echo "$(tput bold)$(tput setaf 1)Warning: $*$(tput sgr0)"; }
plain_version() {
VERSION=$(sed 's/\..*//' /etc/debian_version)
echo "$VERSION"
}
check_sanity() {
	# Do some sanity checking.
	if [ $(/usr/bin/id -u) != "0" ]
	then
		die 'Must be run by root user'
	fi
    if [[ $(plain_version) -lt 7 ]] ;
        then
            die "Distribution is not supported. Debian 7 or above required."
    fi
MACHINE_TYPE=`uname -m`
    if [[ ${MACHINE_TYPE} == arm* ]] ; then
        die "ARM processors are not supported."
    fi
}
function get_ip {
IP=$(ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1)
echo "$IP"
}
function get_external_ip {
ip=$(curl -s http://v4.ident.me/ |cut -d " " -f 5)
echo "$ip"
}
function get_version {
version=$(dpkg -s $1 | grep 'Version')
print_info "$version"
}
function dotdeb_php_repo {
file="/etc/apt/sources.list.d/dotdeb_php.list"
if [ ! -f "$file" ]
then
touch /etc/apt/sources.list.d/dotdeb_php.list
echo "deb http://packages.dotdeb.org wheezy-php56 all" >> /etc/apt/sources.list.d/dotdeb_php.list
echo "deb-src http://packages.dotdeb.org wheezy-php56 all" >> /etc/apt/sources.list.d/dotdeb_php.list
wget http://www.dotdeb.org/dotdeb.gpg &> /dev/null
apt-key add dotdeb.gpg &> /dev/null
wait
rm dotdeb.gpg
fi
apt-get update &> /dev/null
wait
}
function dotdeb_php_7_repo {
file="/etc/apt/sources.list.d/dotdeb_php.list"
if [ ! -f "$file" ]
then
touch /etc/apt/sources.list.d/dotdeb_php.list
fi
if [ $(plain_version) = "8" ];
then
echo "deb http://packages.dotdeb.org jessie all" >> /etc/apt/sources.list.d/dotdeb_php.list
echo "deb-src http://packages.dotdeb.org jessie all" >> /etc/apt/sources.list.d/dotdeb_php.list
fi
wget http://www.dotdeb.org/dotdeb.gpg &> /dev/null
apt-key add dotdeb.gpg &> /dev/null
wait
rm dotdeb.gpg
apt-get update &> /dev/null
wait
}
function hhvm_repo {
file="/etc/apt/sources.list.d/hhvm.list"
if [ ! -f "$file" ]
then
touch /etc/apt/sources.list.d/hhvm.list
fi
if [ $(plain_version) = "7" ]; then
echo deb "http://dl.hhvm.com/debian wheezy main" >> /etc/apt/sources.list.d/hhvm.list
elif [ $(plain_version) = "8" ]; then
echo deb "http://dl.hhvm.com/debian jessie main" >> /etc/apt/sources.list.d/hhvm.list
fi
apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0x5a16e7281be7a449  &> /dev/null
wait
apt-get update &> /dev/null
}
function nginx_repo {
clear
print_info "Installing nginx..."
file="/etc/apt/sources.list.d/nginx.list"
if [ ! -f "$file" ]
then
touch /etc/apt/sources.list.d/nginx.list
fi
>/etc/apt/sources.list.d/nginx.list
if [[ $web = "1" ]] && [[ $(plain_version) = "7" ]];
then
echo "deb http://nginx.org/packages/debian/ wheezy nginx" >> /etc/apt/sources.list.d/nginx.list
echo "deb-src http://nginx.org/packages/debian/ wheezy nginx" >> /etc/apt/sources.list.d/nginx.list
elif [[ $web = "1" ]] && [[ $(plain_version) = "8" ]];
then
echo "deb http://nginx.org/packages/debian/ jessie nginx" >> /etc/apt/sources.list.d/nginx.list
echo "deb-src http://nginx.org/packages/debian/ jessie nginx" >> /etc/apt/sources.list.d/nginx.list
elif [[ $web = "2" ]] && [[ $(plain_version) = "7" ]];
then
echo "deb http://nginx.org/packages/mainline/debian/ wheezy nginx" >> /etc/apt/sources.list.d/nginx.list
echo "deb-src http://nginx.org/packages/mainline/debian/ wheezy nginx" >> /etc/apt/sources.list.d/nginx.list
elif [[ $web = "2" ]] && [[ $(plain_version) = "8" ]];
then
echo "deb http://nginx.org/packages/mainline/debian/ jessie nginx" >> /etc/apt/sources.list.d/nginx.list
echo "deb-src http://nginx.org/packages/mainline/debian/ jessie nginx" >> /etc/apt/sources.list.d/nginx.list
fi
wget http://nginx.org/keys/nginx_signing.key &> /dev/null
apt-key add nginx_signing.key &> /dev/null
wait
rm nginx_signing.key
apt-get update &> /dev/null
wait
}
function mariadb_repo {
file="/etc/apt/sources.list.d/mariadb.list"
if [ ! -f "$file" ]
then
touch /etc/apt/sources.list.d/mariadb.list
apt-get install software-properties-common -y &> /dev/null
fi
if [[ $web = "1" ]] && [[ $(plain_version) = "7" ]];
then
echo deb [arch=amd64,i386] "http://ams2.mirrors.digitalocean.com/mariadb/repo/10.1/debian wheezy main" >> /etc/apt/sources.list.d/hhvm.list
else
echo deb [arch=amd64,i386] "http://ams2.mirrors.digitalocean.com/mariadb/repo/10.1/debian jessie main" >> /etc/apt/sources.list.d/hhvm.list
fi
apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0xcbcb082a1bb943db &> /dev/null
apt-get update  &> /dev/null
apt-get install software-properties-common -y &> /dev/null
wait
apt-get update &> /dev/null
wait
}
function mysql_opt {
mysqladmin -u root password "$dbpass"
mysql -u root -p"$dbpass" -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1')"
mysql -u root -p"$dbpass" -e "DELETE FROM mysql.user WHERE User=''"
mysql -u root -p"$dbpass" -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%'"
mysql -u root -p"$dbpass" -e "FLUSH PRIVILEGES"
sed -i '/skip-external-locking/ a\innodb=OFF' /etc/mysql/my.cnf
sed -i '/innodb=OFF/ a\default-storage-engine=MyISAM' /etc/mysql/my.cnf
sed -i "s|.*default_storage_engine.*|#|" /etc/mysql/my.cnf
print_info "Restarting services..."
service mysql restart &> /dev/null
}
function rand {
rand=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)
echo "$rand"
}
function choice_menu {
    print_info "Install nginx with HTTPS ? [y/n]"
    read -s -n 1 ssl
    if [[ $ssl != [YyNn] ]];
    then
    clear
    print_warn "Error in input, try again"
    exit 1
    fi
if [ $ssl = "y" ]; then
    clear
    print_info "Please choose a SSL Certificate"
    print_info "1) Self signed"
    print_info "2) Let's Encrypt  (Domain required)"
    read -s -n 1 sslv
    if [[ $sslv != [Ee12] ]];
    then
    print_warn "Invalid choice, try again"
    exit 1
    fi
    fi
    clear
if [[ -z $php ]]; then
    print_info "Install PHP or HHVM ? (y/n)"
    read -s -n 1 php
    if [[ $php != [YyNn] ]];
    then
    clear
    print_warn "Error in input, try again"
    exit 1
    fi
fi
if [ $php = "y" ]; then
    print_info "Please choose which PHP version to install"
    print_info "1) PHP 5.6"
    if [ $(plain_version) = "8" ]; then
    print_info "2) PHP 7.0"
    fi
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
    print_info "3) HHVM"
fi
    read -s -n 1 phpv
    if [[ $phpv != [Ee123] ]];
    then
    print_warn "Invalid choice, try again"
    exit 1
    fi
    fi
    clear
if [[ -z $db ]]; then
    print_info "Install MariaDB Server ? (y/n)"
    read -s -n 1 db
    if [[ $db != [YyNn] ]];
    then
    clear
    print_warn "Error in input, try again"
    exit 1
    fi
fi
    if [[ $db = "n" ]]
    then
    clear
if [[ -z $db1 ]]; then
    print_info "Install MySQL Server ? (y/n)"
    read -s -n 1 db1
    if [[ $db1 != [YyNn] ]];
    then
    clear
    print_warn "Error in input, try again"
    exit 1
    fi
    fi
fi
    if [[ $php = "y" ]] && [[ $db == 'y' || $db1 == 'y' ]];
    then
    clear
    print_info "Install phpMyAdmin [y/n]"
    read -s -n 1 phpadm
    if [[ $phpadm != [YyNn] ]];
    then
    clear
    print_warn "Error in input, try again"
    exit 1
    fi
    fi

    if [[ $db = "y" ]] || [[ $db1 = "y" ]]
    then
    unset dbpass
    print_info "Enter a password for the MySQL root user:"
    while IFS= read -p "$prompt" -r -s -n 1 char
    do
        if [[ $char == $'\0' ]]
        then
            break
        fi
        prompt='*'
        dbpass+="$char"
    done
    echo ""
    if [[ -z $dbpass ]];
    then
    clear
    print_warn "MySql password can not be blank !"
    exit 1
    fi
    fi
    if [[ $sslv = "2" ]];
    then
    print_info ""
    print_warn "**********Notice**********"
    print_info "The domain you plan on using"
    print_info "should already resolve to the"
    print_info "servers main ip address."
    print_info "This goes for both www.domain.com"
    print_info "and domain.com"
    print_info "Else Let's Encrypt will fail."
    print_info "And nginx won't start."
    print_warn "**********Notice**********"
    print_info ""
    print_info  "Enter Domain name (without www)"
    read d
    print_info "Enter a valid email"
    read mail
    print_info "Please wait ..."
    if [[ -z $d ]];
    then
    clear
    print_warn "Domain name not entered. Aborting."
    exit 1
    fi
    else
    print_info "Enter Domain, leave blank to use IP"
    read d
    print_info "Please wait ..."
    fi
}
php_version() {
while true; do
print_info "Please choose which PHP version to install"
print_info "1) PHP 5.6"
print_info "2) PHP 7.0"
print_info "3) HHVM"
print_info "e) Exit"
read choice
case $choice in
1)
install_php
break
;;
2)
install_php7
break
;;
3)
install_hhvm
break
;;
e|E)
break
;;
     *)
     print_warn "That is not a valid choice, try a number from 1 to 3."
     ;;
esac
done
}
############################################################
# Apps
############################################################
function install_nginx {
    check_install nginx 1 "ngninx is already installed" v
    choice_menu
    apt-get install curl -y &> /dev/null
    if which apache2 >/dev/null; then
    print_info "Apache2 detected, please wait while we remove it..."
    service apache2 stop &> /dev/null
    apt-get --purge remove apache2 -y &> /dev/null
    fi
    nginx_repo
    DEBIAN_FRONTEND=noninteractive apt-get install -y nginx &> /dev/null
    /bin/cat <<"EOM" >/etc/nginx/conf.d/default.conf
 server {
    listen 80 default_server;
    listen [::]:80 default_server ipv6only=on;

    root /usr/share/nginx/html;
    index index.php index.html index.htm;

    server_name _;

    location / {
        try_files $uri $uri/ =404;
    }

    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
        root /usr/share/nginx/html;
    }
	location ~ \.php$ {
        try_files $uri $uri/ =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:/var/run/php5-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_index index.php;
        include fastcgi_params;
    }
	location = /favicon.ico {
        log_not_found off;
        access_log off;
    }
    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }
    location ~ /\. {
        deny all;
        log_not_found off;
        access_log off;
    }

    location ~* /(?:uploads|files)/.*\.php$ {
        deny all;
    }
	location ~ \.(eot|ttf|woff|svg|css)$ {
	    add_header Access-Control-Allow-Origin "*";
	}
 	location ~* \.(js|css|png|jpg|jpeg|gif|ico)$ {
        expires max;
        log_not_found off;
        access_log off;
    }
}
EOM
if [ -z "$d" ] ; then
d="$(get_external_ip)"
fi
sed -i "s|.*server_name.*|        server_name "$d";|" /etc/nginx/conf.d/default.conf
sed -i "s|.*user.*nginx.*|user www-data;|" /etc/nginx/nginx.conf
cpu_count=`grep -c ^processor /proc/cpuinfo`
sed -i "s|.*worker_processes.*[0-9].*|worker_processes $cpu_count;|" /etc/nginx/nginx.conf
sed -i "s|.*    #gzip  on;.*|    gzip  on;|" /etc/nginx/nginx.conf
sed -i '/    gzip  on;/ a\    gzip_vary on;' /etc/nginx/nginx.conf
sed -i '/    gzip_vary on;/ a\    gzip_proxied any;' /etc/nginx/nginx.conf
sed -i '/    gzip_proxied any;/ a\    gzip_comp_level 6;' /etc/nginx/nginx.conf
sed -i '/    gzip_comp_level 6;/ a\    gzip_buffers 16 8k;' /etc/nginx/nginx.conf
sed -i '/    gzip_buffers 16 8k;/ a\    gzip_http_version 1.1;' /etc/nginx/nginx.conf
sed -i '/    gzip_http_version 1.1;/ a\    gzip_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript;' /etc/nginx/nginx.conf
sed -i '/.*sendfile.*;/ a\    server_tokens   off; ' /etc/nginx/nginx.conf
if [[ $sslv = "1" ]]
then
setup_selfsigned
elif [[ $sslv = "2" ]]
then
setup_letsencrypt
else
if which ufw >/dev/null; then
ufw allow 80/tcp &> /dev/null
ufw disable &> /dev/null
ufw --force enable &> /dev/null
fi
service nginx restart &>  /dev/null
    print_done "ngninx successfully installed."
fi
if [ $php = "y" ] && [ $phpv = "1" ] ; then
install_php
elif
[ $php = "y" ] && [ $phpv = "2" ] ; then
install_php7
elif
[ $php = "y" ] && [ $phpv = "3" ] ; then
install_hhvm
fi
if [[ $db = "y" ]]
then
install_mariadb
fi
if [[ $db1 = "y" ]]
then
install_mysql
fi
if [[ $phpadm = "y" ]]
then
install_phpmyadmin
fi
}
setup_selfsigned() {
print_info "Setting up SSL Certificate ..."
apt-get install openssl &> /dev/null
mkdir -p /etc/nginx/ssl
cd /etc/nginx/ssl
openssl req -sha256 -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/nginx.key -out /etc/nginx/ssl/nginx.crt -subj "/C=US/ST=defaultstate/L=defaultcity/O=myorg/CN="$d"" &> /dev/null
wait
chmod 600 /etc/nginx/ssl/nginx.key
rm /etc/nginx/conf.d/default.conf
wget -O /etc/nginx/conf.d/default.conf https://raw.githubusercontent.com/eunas/gotdeb/master/resources/default-ssl.conf --no-check-certificate &> /dev/null
wait
sed -i "s|        ssl_certificate /etc/letsencrypt/live/domain/fullchain.pem;|        ssl_certificate /etc/nginx/ssl/nginx.crt;|" /etc/nginx/conf.d/default.conf
sed -i "s|        ssl_certificate_key /etc/letsencrypt/live/domain/privkey.pem;|        ssl_certificate_key /etc/nginx/ssl/nginx.key;|" /etc/nginx/conf.d/default.conf
sed -i "s|        server_name domain www.domain;|        server_name "$d";|" /etc/nginx/conf.d/default.conf
sed -i "s|        ssl_dhparam /etc/letsencrypt/dhparams.pem;|        ssl_dhparam /etc/nginx/ssl/dhparams.pem;|" /etc/nginx/conf.d/default.conf
if [ $web = "1" ] ; then
sed -i "s|.*listen        443.*|       listen        443 ssl;|" /etc/nginx/conf.d/default.conf
fi
cd /etc/nginx/ssl/
openssl dhparam -out dhparams.pem 2048 &> /dev/null
chmod 600 dhparams.pem
if which ufw >/dev/null; then
ufw allow 80/tcp &> /dev/null
ufw allow 443/tcp &> /dev/null
ufw disable &> /dev/null
ufw --force enable &> /dev/null
fi
service nginx restart
print_done "ngninx successfully installed."
}
setup_letsencrypt() {
print_info "Setting up Let's Encrypt. This might take a while..."
DEBIAN_FRONTEND=noninteractive apt-get -y install git bc &> /dev/null
wait
git clone https://github.com/letsencrypt/letsencrypt /opt/letsencrypt &> /dev/null
wait
service nginx stop
wait
/opt/letsencrypt/letsencrypt-auto certonly --test-cert --standalone --agree-tos --email "$mail" -d "$d" -d www."$d" &> /dev/null
wait
rm /etc/nginx/conf.d/default.conf
wget -O /etc/nginx/conf.d/default.conf https://raw.githubusercontent.com/eunas/gotdeb/master/resources/default-ssl.conf --no-check-certificate &> /dev/null
wait
sed -i "s|        ssl_certificate /etc/letsencrypt/live/domain/fullchain.pem;|        ssl_certificate /etc/letsencrypt/live/"$d"/fullchain.pem;|" /etc/nginx/conf.d/default.conf
sed -i "s|        ssl_certificate_key /etc/letsencrypt/live/domain/privkey.pem;|        ssl_certificate_key /etc/letsencrypt/live/"$d"/privkey.pem;|" /etc/nginx/conf.d/default.conf
sed -i "s|        server_name domain www.domain;|        server_name "$d" www."$d";|" /etc/nginx/conf.d/default.conf
if [ $web = "1" ] ; then
sed -i "s|.*listen        443.*|       listen        443 ssl;|" /etc/nginx/conf.d/default.conf
fi
cd /etc/letsencrypt/
openssl dhparam -out dhparams.pem 2048
chmod 600 dhparams.pem
cp /opt/letsencrypt/examples/cli.ini /usr/local/etc/le-renew-webroot.ini
sed -i "s|# email = foo@example.com|email = "$mail"|" /usr/local/etc/le-renew-webroot.ini
sed -i "s|# domains = example.com, www.example.com|domains = "$d", www."$d"|" /usr/local/etc/le-renew-webroot.ini
sed -i "s|# webroot-path = /usr/share/nginx/html|webroot-path = /usr/share/nginx/html|" /usr/local/etc/le-renew-webroot.ini
wget -O /usr/local/sbin/le-renew-webroot https://gist.githubusercontent.com/thisismitch/e1b603165523df66d5cc/raw/fbffbf358e96110d5566f13677d9bd5f4f65794c/le-renew-webroot  &> /dev/null
chmod +x /usr/local/sbin/le-renew-webroot
(crontab -l 2>/dev/null; echo "30 2 * * 1 /usr/local/sbin/le-renew-webroot >> /var/log/le-renewal.log") | crontab -
if which ufw >/dev/null; then
ufw allow 80/tcp &> /dev/null
ufw allow 443/tcp &> /dev/null
ufw disable &> /dev/null
ufw --force enable &> /dev/null
fi
service nginx start
print_done "ngninx successfully installed."
}
function install_php {
    if [ -x /usr/sbin/nginx ]; then
    check_install php5-fpm 1 "php5-fpm is already installed" v
    print_info "Installing PHP ..."
    if [ $(plain_version) = "7" ]; then
    dotdeb_php_repo
    fi
    DEBIAN_FRONTEND=noninteractive apt-get install php5-fpm php5-common php5-mysqlnd php5-sqlite php5-mcrypt php5-curl curl php5-cli php5-gd -y &> /dev/null
    sed -i "s|.*;cgi.fix_pathinfo.*|cgi.fix_pathinfo=0|" /etc/php5/fpm/php.ini
    sed -i "s|.*upload_max_filesize = 2M.*|upload_max_filesize = 128M|" /etc/php5/fpm/php.ini
    sed -i "s|.*post_max_size = 8M.*|post_max_size = 128M|" /etc/php5/fpm/php.ini
    sed -i "s|.*reload signal USR2.*|        #reload signal USR2|" /etc/init/php5-fpm.conf
    touch /usr/share/nginx/html/info.php
/bin/cat <<"EOM" >/usr/share/nginx/html/info.php
    <?php
    phpinfo();
    ?>
EOM
    wait
    service php5-fpm start
    service nginx restart
    print_done "PHP-FPM 5.6 successfully installed."
else
print_warn "No webserver installed. Aborting"
exit 1
fi
}
function install_php7 {
    if [ -x /usr/sbin/nginx ]; then
    check_install php7-fpm 1 "php7-fpm is already installed" v
    print_info "Installing PHP 7 ..."
    dotdeb_php_7_repo
    wait
    DEBIAN_FRONTEND=noninteractive apt-get install php7.0-mysql php7.0 php7.0-fpm php7.0-common curl php7.0-cli php7.0-gd php7.0-mcrypt php7.0-opcache php7.0-curl -y &> /dev/null
    sed -i "s|.*;cgi.fix_pathinfo.*|cgi.fix_pathinfo=0|" /etc/php/7.0/fpm/php.ini
    sed -i "s|.*upload_max_filesize = 2M.*|upload_max_filesize = 128M|" /etc/php/7.0/fpm/php.ini
    sed -i "s|.*post_max_size = 8M.*|post_max_size = 128M|" /etc/php/7.0/fpm/php.ini
    sed -i "s|        fastcgi_pass unix:/var/run/php5-fpm.sock;|        fastcgi_pass unix:/var/run/php/php7.0-fpm.sock;|" /etc/nginx/conf.d/default.conf
    touch /usr/share/nginx/html/info.php
/bin/cat <<"EOM" >/usr/share/nginx/html/info.php
    <?php
    phpinfo();
    ?>
EOM
    wait
    service php7.0-fpm start
    service nginx restart
    print_done "PHP-FPM 7.0 successfully installed."
else
print_warn "No webserver installed. Aborting"
exit 1
fi
}
function install_hhvm {
    if [ -x /usr/sbin/nginx ]; then
    print_info "Installing HHVM ..."
    hhvm_repo
    wait
    apt-get install php5-mysql hhvm curl -y &> /dev/null
    sed -i "s|        fastcgi_pass unix:/var/run/php5-fpm.sock;|        fastcgi_pass unix:/var/run/hhvm/hhvm.sock;|" /etc/nginx/conf.d/default.conf
    sed -i '/hhvm.server.port = 9000/ a\hhvm.server.file_socket=/var/run/hhvm/hhvm.sock' /etc/hhvm/server.ini
    sed -i "s|hhvm.server.port = 9000|;hhvm.server.port = 9000|" /etc/hhvm/server.ini
    touch /usr/share/nginx/html/info.php
/bin/cat <<"EOM" >/usr/share/nginx/html/info.php
    <?php
    phpinfo();
    ?>
EOM
    wait
    service hhvm restart
    service nginx restart
    print_done "HHVM successfully installed."
else
print_warn "No webserver installed. Aborting"
exit 1
fi
}
function install_mysql {
check_install mysql-server 1 "MySQL is already installed"
check_install mariadb-server 1 "MariaDB is the current DB server. Can't install MySQL"
if [ -z "$dbpass" ];
then
unset dbpass
    print_info "Enter a password for the MySQL root user:"
    while IFS= read -p "$prompt" -r -s -n 1 char
    do
        if [[ $char == $'\0' ]]
        then
            break
        fi
        prompt='*'
        dbpass+="$char"
    done
fi
clear
print_info "Installing MySql Server, please wait..."
apt-get update &> /dev/null
wait
DEBIAN_FRONTEND=noninteractive apt-get -y install mysql-server mysql-client &> /dev/null
wait
mysql_opt $dbpass
print_done "MySQL successfully installed."
}
function install_mariadb {
check_install mysql-server  1 "MySQL is the current DB server. Can't install Mariadb"
check_install mariadb-server 1 "MariaDB Server is already installed"
if [ -z "$dbpass" ];
then
unset dbpass
    print_info "Enter a password for the MySQL root user:"
    while IFS= read -p "$prompt" -r -s -n 1 char
    do
        if [[ $char == $'\0' ]]
        then
            break
        fi
        prompt='*'
        dbpass+="$char"
    done
fi
clear
print_info "Installing MariaDB Server, please wait...";
mariadb_repo
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y &> /dev/null
wait
DEBIAN_FRONTEND=noninteractive apt-get -y install python-software-properties mariadb-server mariadb-client &> /dev/null
wait
mysql_opt $dbpass
sed -i '/default-storage-engine=MyISAM/ a\default-tmp-storage-engine=MyISAM' /etc/mysql/my.cnf
print_done "MariaDB successfully installed."
}
function install_phpmyadmin {
check_install phpmyadmin 1 "phpMyAdmin is already installed" v
check_install nginx 0 "Nginx is not installed."
if [[ ! -f /usr/sbin/php5-fpm ]] && [[ ! -f /usr/sbin/php-fpm7.0 ]] && [[ ! -f /usr/bin/hhvm ]]; then
 print_warn "PHP or HHVM is not installed."
exit 1
fi
if ((! $(ps -ef | grep -v grep | grep mysql | wc -l) > 0 ))
then
        print_warn "The MySQL server is stopped or not installed.";
        exit 1

fi
print_info "Installing phpMyAdmin..."
apt-get install unzip -y &> /dev/null
wget -O /tmp/phpmyadmin.zip https://github.com/phpmyadmin/phpmyadmin/archive/STABLE.zip &>/dev/null
wait
unzip /tmp/phpmyadmin.zip -d /tmp &> /dev/null
wait
rm /tmp/phpmyadmin.zip
mkdir /usr/share/phpmyadmin
mv /tmp/phpmyadmin-STABLE/* /usr/share/phpmyadmin
chown -R www-data:www-data /usr/share/phpmyadmin
cp /usr/share/phpmyadmin/config.sample.inc.php  /usr/share/phpmyadmin/config.inc.php
sed -i "s|.*blowfish_secret.*|\$cfg['blowfish_secret'] = '$(rand)';|" /usr/share/phpmyadmin/config.inc.php
sed -i '/.*blowfish_secret.*/ a\$cfg['PmaNoRelation_DisableWarning'] = true;' /usr/share/phpmyadmin/config.inc.php
ln -s /usr/share/phpmyadmin/ /usr/share/nginx/html
if [[ -f /usr/sbin/php-fpm7.0 ]]; then
chown -R www-data:www-data /var/lib/php/sessions
fi
if [[ -f /usr/bin/hhvm ]]; then
echo "\$cfg['Servers'][\$i]['port'] = '3306';" >> /usr/share/phpmyadmin/config.inc.php
sed -i "s|.*localhost.*|\$cfg['Servers'][\$i]['host'] = '127.0.0.1';|" /usr/share/phpmyadmin/config.inc.php
fi
service nginx restart
print_done "phpMyAdmin successfully installed."
}
function install_webserver  {
clear
print_info "Please choose which version to install"
    print_info "1) nginx 1.8.x"
    print_info "2) nginx 1.9.x"
    print_info "e) Exit"
    read -s -n 1 web
    if [[ $web != [Ee123] ]];
    then
    print_warn "Invalid choice, try again"
    install_webserver
    fi
    if [[ $web = [12] ]];
    then
    install_nginx
    fi
    if [[ $web = "e" ]]
    then
    exit 1
    fi
}
function install_pureftpd {
check_install pure-ftpd 1 "Pure-ftpd is already installed." v
print_info "Define port for Pure-ftpd, leave blank for port 21"
read p
print_info "Installing Pure-FTPd..."
apt-get update &> /dev/null
wait
DEBIAN_FRONTEND=noninteractive apt-get install pure-ftpd -y &> /dev/null
wait
if [ -z "$p" ] ; then
p="21"
fi
echo "yes" > /etc/pure-ftpd/conf/Daemonize
echo "yes" > /etc/pure-ftpd/conf/NoAnonymous
echo "yes" > /etc/pure-ftpd/conf/ChrootEveryone
echo "2" > /etc/pure-ftpd/conf/TLS
echo "$p" > /etc/pure-ftpd/conf/Bind
openssl req -x509 -nodes -days 7300 -newkey rsa:2048 -keyout /etc/ssl/private/pure-ftpd.pem -out /etc/ssl/private/pure-ftpd.pem -subj "/C=US/ST=defaultstate/L=defaultcity/O=myorg/CN=localhost"
if which ufw >/dev/null; then
ufw allow "$p"/tcp &> /dev/null
ufw disable &> /dev/null
ufw --force enable &> /dev/null
fi
service pure-ftpd restart &> /dev/null
print_done "Pure-FTPd with FTPS support successfully installed."
}
function install_openvpn {
if [[ ! -e /dev/net/tun ]]; then
	print_warn "TUN/TAP is not available"
	exit 1
fi
if grep -qs "CentOS release 5" "/etc/redhat-release"; then
	echo "CentOS 5 is too old and not supported"
	exit 2
fi
if [[ -e /etc/debian_version ]]; then
	OS=debian
	RCLOCAL='/etc/rc.local'
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	OS=centos
	RCLOCAL='/etc/rc.d/rc.local'
	# Needed for CentOS 7
	chmod +x /etc/rc.d/rc.local
else
	echo "Looks like you aren't running this installer on a Debian, Ubuntu or CentOS system"
	exit 3
fi

newclient () {
	# Generates the custom client.ovpn
	cp /etc/openvpn/client-common.txt ~/$1.ovpn
	echo "<ca>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/$1.ovpn
	echo "</ca>" >> ~/$1.ovpn
	echo "<cert>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/issued/$1.crt >> ~/$1.ovpn
	echo "</cert>" >> ~/$1.ovpn
	echo "<key>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/private/$1.key >> ~/$1.ovpn
	echo "</key>" >> ~/$1.ovpn
}


# Try to get our IP from the system and fallback to the Internet.
# I do this to make the script compatible with NATed servers (lowendspirit.com)
# and to avoid getting an IPv6.
IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
if [[ "$IP" = "" ]]; then
		IP=$(wget -qO- ipv4.icanhazip.com)
fi


if [[ -e /etc/openvpn/server.conf ]]; then
	while :
	do
	clear
		echo "Looks like OpenVPN is already installed"
		echo ""
		echo "What do you want to do?"
		echo "   1) Add a cert for a new user"
		echo "   2) Revoke existing user cert"
		echo "   3) Remove OpenVPN"
		echo "   4) Exit"
		read -p "Select an option [1-4]: " option
		case $option in
			1)
			echo ""
			echo "Tell me a name for the client cert"
			echo "Please, use one word only, no special characters"
			read -p "Client name: " -e -i client CLIENT
			cd /etc/openvpn/easy-rsa/
			./easyrsa build-client-full $CLIENT nopass
			# Generates the custom client.ovpn
			newclient "$CLIENT"
			echo ""
			echo "Client $CLIENT added, certs available at ~/$CLIENT.ovpn"
			exit
			;;
			2)
			# This option could be documented a bit better and maybe even be simplimplified
			# ...but what can I say, I want some sleep too
			NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$NUMBEROFCLIENTS" = '0' ]]; then
				echo ""
				echo "You have no existing clients!"
				exit 5
			fi
			echo ""
			echo "Select the existing client certificate you want to revoke"
			tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			if [[ "$NUMBEROFCLIENTS" = '1' ]]; then
				read -p "Select one client [1]: " CLIENTNUMBER
			else
				read -p "Select one client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
			fi
			CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
			cd /etc/openvpn/easy-rsa/
			./easyrsa --batch revoke $CLIENT
			./easyrsa gen-crl
			rm -rf pki/reqs/$CLIENT.req
			rm -rf pki/private/$CLIENT.key
			rm -rf pki/issued/$CLIENT.crt
			rm -rf /etc/openvpn/crl.pem
			cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
			# And restart
			if pgrep systemd-journal; then
				systemctl restart openvpn@server.service
			else
				if [[ "$OS" = 'debian' ]]; then
					/etc/init.d/openvpn restart
				else
					service openvpn restart
				fi
			fi
			echo ""
			echo "Certificate for client $CLIENT revoked"
			exit
			;;
			3)
			echo ""
			read -p "Do you really want to remove OpenVPN? [y/n]: " -e -i n REMOVE
			if [[ "$REMOVE" = 'y' ]]; then
				PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
				if pgrep firewalld; then
					# Using both permanent and not permanent rules to avoid a firewalld reload.
					firewall-cmd --zone=public --remove-port=$PORT/udp
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --zone=public --remove-port=$PORT/udp
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
				fi
				if iptables -L | grep -qE 'REJECT|DROP'; then
					sed -i "/iptables -I INPUT -p udp --dport $PORT -j ACCEPT/d" $RCLOCAL
					sed -i "/iptables -I FORWARD -s 10.8.0.0\/24 -j ACCEPT/d" $RCLOCAL
					sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT/d" $RCLOCAL
				fi
				sed -i '/iptables -t nat -A POSTROUTING -s 10.8.0.0\/24 -j SNAT --to /d' $RCLOCAL
				if sestatus | grep "Current mode" | grep -qs "enforcing"; then
					if [[ "$PORT" != '1194' ]]; then
						semanage port -d -t openvpn_port_t -p udp $PORT
					fi
				fi
				if [[ "$OS" = 'debian' ]]; then
					apt-get remove --purge -y openvpn openvpn-blacklist
				else
					yum remove openvpn -y
				fi
				rm -rf /etc/openvpn
				rm -rf /usr/share/doc/openvpn*
				echo ""
				echo "OpenVPN removed!"
			else
				echo ""
				echo "Removal aborted!"
			fi
			exit
			;;
			4) exit;;
		esac
	done
else
	clear
	print_info 'Welcome to this quick OpenVPN "road warrior" installer'
	print_info ""
	# OpenVPN setup and first user creation
	print_info "I need to ask you a few questions before starting the setup"
	print_info "You can leave the default options and just press enter if you are ok with them"
	print_info ""
	print_info "First I need to know the IPv4 address of the network interface you want OpenVPN"
	print_info "listening to."
	read -p "IP address: " -e -i $IP IP
	print_info ""
	print_info "What port do you want for OpenVPN?"
	read -p "Port: " -e -i 1194 PORT
	print_info ""
	print_info "What DNS do you want to use with the VPN?"
	print_info "   1) Current system resolvers"
	print_info "   2) Google"
	print_info "   3) OpenDNS"
	print_info "   4) NTT"
	print_info "   5) Hurricane Electric"
	read -p "DNS [1-6]: " -e -i 1 DNS
	print_info ""
	print_info "Finally, tell me your name for the client cert"
	print_info "Please, use one word only, no special characters"
	read -p "Client name: " -e -i client CLIENT
	print_info ""
	print_info "Okay, that was all I needed. We are ready to setup your OpenVPN server now"
	read -n1 -r -p "Press any key to continue..."
		if [[ "$OS" = 'debian' ]]; then
		apt-get update
		apt-get install openvpn iptables openssl ca-certificates -y
	else
		# Else, the distro is CentOS
		yum install epel-release -y
		yum install openvpn iptables openssl wget ca-certificates -y
	fi
	# An old version of easy-rsa was available by default in some openvpn packages
	if [[ -d /etc/openvpn/easy-rsa/ ]]; then
		rm -rf /etc/openvpn/easy-rsa/
	fi
	# Get easy-rsa
	wget -O ~/EasyRSA-3.0.1.tgz https://github.com/OpenVPN/easy-rsa/releases/download/3.0.1/EasyRSA-3.0.1.tgz
	tar xzf ~/EasyRSA-3.0.1.tgz -C ~/
	mv ~/EasyRSA-3.0.1/ /etc/openvpn/
	mv /etc/openvpn/EasyRSA-3.0.1/ /etc/openvpn/easy-rsa/
	chown -R root:root /etc/openvpn/easy-rsa/
	rm -rf ~/EasyRSA-3.0.1.tgz
	cd /etc/openvpn/easy-rsa/
	# Create the PKI, set up the CA, the DH params and the server + client certificates
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	./easyrsa gen-dh
	./easyrsa build-server-full server nopass
	./easyrsa build-client-full $CLIENT nopass
	./easyrsa gen-crl
	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/server.crt pki/private/server.key /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
	# Generate server.conf
	echo "port $PORT
proto udp
dev tun
sndbuf 0
rcvbuf 0
ca ca.crt
cert server.crt
key server.key
dh dh.pem
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" > /etc/openvpn/server.conf
	echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server.conf
	# DNS
	case $DNS in
		1)
		# Obtain the resolvers from resolv.conf and use them for OpenVPN
		grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
			echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server.conf
		done
		;;
		2)
		echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
		;;
		3)
		echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server.conf
		;;
		4)
		echo 'push "dhcp-option DNS 129.250.35.250"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 129.250.35.251"' >> /etc/openvpn/server.conf
		;;
		5)
		echo 'push "dhcp-option DNS 74.82.42.42"' >> /etc/openvpn/server.conf
		;;
	esac
	echo "keepalive 10 120
comp-lzo
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify crl.pem" >> /etc/openvpn/server.conf
	# Enable net.ipv4.ip_forward for the system
	if [[ "$OS" = 'debian' ]]; then
		sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf
	else
		# CentOS 5 and 6
		sed -i 's|net.ipv4.ip_forward = 0|net.ipv4.ip_forward = 1|' /etc/sysctl.conf
		# CentOS 7
		if ! grep -q "net.ipv4.ip_forward=1" "/etc/sysctl.conf"; then
			echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
		fi
	fi
	# Avoid an unneeded reboot
	echo 1 > /proc/sys/net/ipv4/ip_forward
	# Set NAT for the VPN subnet
	iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP
	sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP" $RCLOCAL
	if pgrep firewalld; then
		# We don't use --add-service=openvpn because that would only work with
		# the default port. Using both permanent and not permanent rules to
		# avoid a firewalld reload.
		firewall-cmd --zone=public --add-port=$PORT/udp
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --zone=public --add-port=$PORT/udp
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
	fi
	if iptables -L | grep -qE 'REJECT|DROP'; then
		# If iptables has at least one REJECT rule, we asume this is needed.
		# Not the best approach but I can't think of other and this shouldn't
		# cause problems.
		iptables -I INPUT -p udp --dport $PORT -j ACCEPT
		iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
		iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
		sed -i "1 a\iptables -I INPUT -p udp --dport $PORT -j ACCEPT" $RCLOCAL
		sed -i "1 a\iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
		sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
	fi
	# If SELinux is enabled and a custom port was selected, we need this
	if sestatus | grep "Current mode" | grep -qs "enforcing"; then
		if [[ "$PORT" != '1194' ]]; then
			# semanage isn't available in CentOS 6 by default
			if ! which semanage > /dev/null 2>&1; then
				yum install policycoreutils-python -y
			fi
			semanage port -a -t openvpn_port_t -p udp $PORT
		fi
	fi
	# And finally, restart OpenVPN
	if [[ "$OS" = 'debian' ]]; then
		# Little hack to check for systemd
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
		else
			/etc/init.d/openvpn restart
		fi
	else
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
			systemctl enable openvpn@server.service
		else
			service openvpn restart
			chkconfig openvpn on
		fi
	fi
	# Try to detect a NATed connection and ask about it to potential LowEndSpirit users
	EXTERNALIP=$(wget -qO- ipv4.icanhazip.com)
	if [[ "$IP" != "$EXTERNALIP" ]]; then
		print_info ""
		print_info "Looks like your server is behind a NAT!"
		print_info ""
		print_info "If your server is NATed (LowEndSpirit), I need to know the external IP"
		print_info "If that's not the case, just ignore this and leave the next field blank"
		read -p "External IP: " -e USEREXTERNALIP
		if [[ "$USEREXTERNALIP" != "" ]]; then
			IP=$USEREXTERNALIP
		fi
	fi
	# client-common.txt is created so we have a template to add further users later
	echo "client
dev tun
proto udp
sndbuf 0
rcvbuf 0
remote $IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
comp-lzo
verb 3" > /etc/openvpn/client-common.txt
	# Generates the custom client.ovpn
if which ufw >/dev/null; then
ufw allow "$PORT"/tcp &> /dev/null
ufw disable &> /dev/null
ufw --force enable &> /dev/null
fi
	newclient "$CLIENT"
	print_info ""
	print_info "Finished!"
	print_info ""
	print_info "Your client config is available at ~/$CLIENT.ovpn"
	print_info "If you want to add more clients, you simply need to run this script another time!"
fi
}
function install_squid3 {
check_install squid3 1 "Squid3 is already installed" v
print_info ""
print_info "-----------------------------------------------------"
print_info "WELCOME TO THE SQUID PROXY SERVER INSTALLATION SCRIPT"
print_info "-----------------------------------------------------"
print_info ""
print_info " This script will set up a password protected, elite"
print_info "             proxy on your target server"
print_info ""
print_info "-----------------------------------------------------"
print_info ""
print_info "Please enter a user name for Squid:"
read u
print_info ""
print_info "Please enter a password:"
read -s p
print_info ""
print_info "Please enter the port squid3 will listen on (Leave blank for default):"
read sp
if [ -z "$sp" ] ; then
sp="3128"
fi
clear
print_info "Installing Squid3, please wait..."
a="`netstat -i | cut -d' ' -f1 | grep eth0`";
b="`netstat -i | cut -d' ' -f1 | grep venet0:0`";

if [ "$a" == "eth0" ]; then
  ip="`/sbin/ifconfig eth0 | awk -F':| +' '/inet addr/{print $4}'`";
elif [ "$b" == "venet0:0" ]; then
  ip="`/sbin/ifconfig venet0:0 | awk -F':| +' '/inet addr/{print $4}'`";
fi

apt-get update &> /dev/null
DEBIAN_FRONTEND=noninteractive apt-get -y install apache2-utils squid3 curl &> /dev/null

rm /etc/squid3/squid.conf

cat > /etc/squid3/squid.conf <<END
acl ip1 myip $ip
tcp_outgoing_address $ip ip1

auth_param basic program /usr/lib/squid3/ncsa_auth /etc/squid3/squid_passwd
acl ncsa_users proxy_auth REQUIRED
http_access allow ncsa_users


acl SSL_ports port 443
acl Safe_ports port 80        # http
acl Safe_ports port 21        # ftp
acl Safe_ports port 443        # https
acl Safe_ports port 1025-65535    # unregistered ports
acl Safe_ports port 280        # http-mgmt
acl Safe_ports port 488        # gss-http
acl Safe_ports port 591        # filemaker
acl Safe_ports port 777        # multiling http
acl CONNECT method CONNECT

http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access deny all
http_port $sp

hierarchy_stoplist cgi-bin ?
coredump_dir /var/spool/squid3
cache deny all

access_log none
cache_store_log none
cache_log /dev/null
logfile_rotate 0

refresh_pattern ^ftp:        1440    20%    10080
refresh_pattern ^gopher:    1440    0%    1440
refresh_pattern -i (/cgi-bin/|\?) 0    0%    0
refresh_pattern .        0    20%    4320

icp_port 0

forwarded_for off

request_header_access Allow allow all
request_header_access Authorization allow all
request_header_access Proxy-Authorization allow all
request_header_access Proxy-Authenticate allow all
request_header_access Cache-Control deny all
request_header_access Content-Encoding allow all
request_header_access Content-Length allow all
request_header_access Content-Type allow all
request_header_access Date allow all
request_header_access Expires allow all
request_header_access Host allow all
request_header_access If-Modified-Since allow all
request_header_access Last-Modified allow all
request_header_access Location allow all
request_header_access Pragma allow all
request_header_access Accept allow all
request_header_access Accept-Charset allow all
request_header_access Accept-Encoding allow all
request_header_access Accept-Language allow all
request_header_access Content-Language allow all
request_header_access Mime-Version allow all
request_header_access Retry-After allow all
request_header_access Title allow all
request_header_access Connection allow all
request_header_access Proxy-Connection allow all
request_header_access User-Agent allow all
request_header_access Cookie allow all
request_header_access All deny all
END
if [ $(plain_version) = "8" ]; then
sed -i "s|.*auth_param basic program.*|auth_param basic program /usr/lib/squid3/basic_ncsa_auth /etc/squid3/squid_passwd|" /etc/squid3/squid.conf
fi
htpasswd -b -c /etc/squid3/squid_passwd $u $p
if which ufw >/dev/null; then
ufw allow "$p"/tcp &> /dev/null
ufw disable &> /dev/null
ufw --force enable &> /dev/null
fi
service squid3 restart

clear

print_info ""
print_info "----------------------------------------------------"
print_info "Squid proxy server set up has been completed."
print_info ""
print_info "You can access your proxy server at $(get_external_ip)"
print_info "on port $sp with user name $u"
print_info ""
print_info "----------------------------------------------------"
print_info ""
}
function configure_ssmtp {
while true; do
print_info "ssmtp needs to be configured to use an external smtp server."
print_info "Remember to set it up for PHP if you need that"
print_info "Configure  ssmtp:"
print_info "1) Setup using Mandrill smtp"
print_info "2) Setup using Gmail smtp"
print_info "3) Configure for PHP"
print_info "e) Exit"
read -n1 choice
case $choice in
1)
print_info "specify email address"
read mmail
print_info "Server hostname"
read mhost
print_info "Your mandril login mail"
read mlogin
print_info "mandril api key"
read -s mapikey
if [[ ! -f "/etc/ssmtp/ssmtp.conf" ]] ;
then
touch /etc/ssmtp/ssmtp.conf
else
>/etc/ssmtp/ssmtp.conf
fi
/bin/cat <<EOM >/etc/ssmtp/ssmtp.conf
# ---- basic config
root=$mmail
AuthMethod=LOGIN
UseSTARTTLS=YES
hostname=$mhost
FromLineOverride=YES
# ---- mandrill config
AuthUser=$mlogin
mailhub=smtp.mandrillapp.com:587
AuthPass=$mapikey
EOM
if [[ ! -f "/etc/ssmtp/revaliases" ]] ;
then
touch /etc/ssmtp/revaliases
else
>/etc/ssmtp/revaliases
fi
/bin/cat <<EOM >/etc/ssmtp/revaliases
root:$mmail:smtp.mandrillapp.com:587
EOM
print_done "ssmtp successfully installed."
break
;;
2)
print_info "specify email address"
read gmail
print_info "Servers hostname"
read ghost
print_info "Gmail address"
read glogin
print_info "Gmail password"
read -s gapikey
if [[ ! -f "/etc/ssmtp/ssmtp.conf" ]] ;
then
touch /etc/ssmtp/ssmtp.conf
else
>/etc/ssmtp/ssmtp.conf
fi
/bin/cat <<EOM >/etc/ssmtp/ssmtp.conf
# ---- basic config
root=$gmail
AuthMethod=LOGIN
UseTLS=YES
UseSTARTTLS=YES
hostname=$ghost
FromLineOverride=YES
# ---- gmail config
AuthUser=$glogin
mailhub=smtp.gmail.com:587
AuthPass=$gapikey
EOM
if [[ ! -f "/etc/ssmtp/revaliases" ]] ;
then
touch /etc/ssmtp/revaliases
else
>/etc/ssmtp/revaliases
fi
/bin/cat <<EOM >/etc/ssmtp/revaliases
root:$gmail:smtp.gmail.com:587
EOM
print_done "ssmtp successfully installed."
break
;;
3)
if [[ ! -f /usr/sbin/php5-fpm ]] && [[ ! -f /usr/sbin/php-fpm7.0 ]] && [[ ! -f /usr/bin/hhvm ]]; then
 print_warn "PHP or HHVM is not installed."
exit 1
fi
if [[ -f /usr/sbin/php5-fpm ]]; then
sed -i "s|.*sendmail_path.*|sendmail_path = /usr/sbin/ssmtp -t|" /etc/php5/fpm/php.ini
elif [[ -f /usr/sbin/php-fpm7.0 ]]; then
sed -i "s|.*sendmail_path.*|sendmail_path = /usr/sbin/ssmtp -t|" /etc/php/7.0/fpm/php.ini
elif [[ -f /usr/bin/hhvm ]]; then
echo "sendmail_path = /usr/sbin/ssmtp -t" >> /etc/hhvm/php.ini
fi
print_done "ssmtp successfully configured."
break
;;
e)
break
;;
     *)
     print_warn "That is not a valid choice, try a number from 1 to 2."
     ;;
esac
done
}
function install_ssmtp {
if which ssmtp >/dev/null; then
configure_ssmtp
else
print_info "Installing ssmtp..."
DEBIAN_FRONTEND=noninteractive apt-get install -y ssmtp &> /dev/null
wait
configure_ssmtp
fi
}
function show_os_arch_version {
if [ $(dpkg-query -W -f='${Status}' lsb-release 2>/dev/null | grep -c "ok installed") -eq 0 ];
then
  apt-get install lsb-release >/dev/null
  wait
fi
	ARCH=$(uname -m | sed 's/x86_//;s/i[3-6]86/32/')

	if [ -f /etc/lsb-release ]; then
		. /etc/lsb-release
		OS=$DISTRIB_ID
		VERSION=$DISTRIB_RELEASE
	elif [ -f /etc/debian_version ]; then
		# Work on Debian and Ubuntu alike
		OS=$(lsb_release -si)
		VERSION=$(lsb_release -sr)
	elif [ -f /etc/redhat-release ]; then
		# Add code for Red Hat and CentOS here
		OS=Redhat
		VERSION=$(uname -r)
	else
		# Pretty old OS? fallback to compatibility mode
		OS=$(uname -s)
		VERSION=$(uname -r)
	fi

	OS_SUMMARY=$OS
	OS_SUMMARY+=" "
	OS_SUMMARY+=$VERSION
	OS_SUMMARY+=" "
	OS_SUMMARY+=$ARCH
	OS_SUMMARY+="bit"

	print_info "$OS_SUMMARY"
}
function user_management {
while true; do
print_info "1) Add user"
print_info "2) Delete user"
print_info "3) List users"
print_info "e) Exit"
read -n1 choice
case $choice in
1)
print_info "Enter username"
read username
useradd -d /home/$username $username
wait
mkdir -p "/home/$username"
chmod 750 /home/$username
chown -R $username /home/$username
wait
passwd $username
print_info "User $username added with home dir /home/$username"
break
;;
2)
echo "Enter username"
read username
deluser $username
print_info "User: $username deleted. Home directory is still intact"
break
;;
3)
echo"------system users------"
cut -d: -f1 /etc/passwd
break
;;
e)
break
;;
     *)
     echo "That is not a valid choice, try a number from 1 to 3."
     ;;
esac
done
}
function system_management {
while true; do
print_info "1) Remove unneeded packages and services"
print_info "2) Install essentials packages"
print_info "3) Update timezone"
print_info "4) System tests"
print_info "5) Secure System"
print_info "6) Speedtest.net"
print_info "7) Get OS Version"
print_info "8) TUN/TAP Status"
print_info "e) Exit"
read -n1 choice
case $choice in
1)
remove_unneeded
break
;;
2)
essentials
break
;;
3)
dpkg-reconfigure tzdata
break
;;
4)
system_tests
break
;;
5)
secure_system
break
;;
6)
run_speedtest
break
;;
7)
show_os_arch_version
break
;;
8)
if [[ ! -e /dev/net/tun ]]; then
	print_info "TUN/TAP is not available"
	else
    print_info "TUN/TAP is available"
fi
break
;;
e)
break
;;
     *)
     print_warn "That is not a valid choice, try a number from 1 to 8."
     ;;
esac
done
}
function remove_unneeded {
    service sendmail stop
    wait
    service apache2 stop
    wait
    service bind9 stop
    wait
	# Some Debian have portmap installed. We don't need that.
	apt-get --purge remove -y portmap

	# Other packages that are quite common in standard OpenVZ templates.
	apt-get --purge remove -y apache2*
    wait
	apt-get --purge remove -y bind9*
    wait
	apt-get --purge remove -y samba*
    wait
	apt-get --purge remove -y nscd
    wait
    apt-get update && apt-get install sysv-rc-conf -y
    wait
    sysv-rc-conf xinetd off
    sysv-rc-conf saslauthd off

	# Need to stop sendmail as removing the package does not seem to stop it.
	if [ -f /usr/lib/sm.bin/smtpd ]
	then
		invoke-rc.d sendmail stop
		apt-get --purge remove -y sendmail-base m4 procmail
	fi
    print_done "You should restart now"
}
function essentials {
print_info "Installing..."
apt-get update &> /dev/null
apt-get install -y nano rcconf lftp unzip  &> /dev/null
print_done "Essentials services installed"
}
function script_about {
print_info "Interactive bash script for VPS or Dedicated servers."
print_info "Build with low end systems in mind. Requires Debian version 7.x or above"
print_info "https://gotdeb.com"
print_info ""
print_info "Credits: Xeoncross, mikel, Falko Timme, road warrior, Nyr and many others",
print_info ""
print_info "Version 1.6.4"
}
function system_tests {
	print_info "Classic I/O test"
	print_info "dd if=/dev/zero of=iotest bs=64k count=16k conv=fdatasync && rm -fr iotest"
	dd if=/dev/zero of=iotest bs=64k count=16k conv=fdatasync && rm -fr iotest

	print_info "Network test"
	print_info "wget cachefly.cachefly.net/100mb.test -O 100mb.test && rm -fr 100mb.test"
	wget cachefly.cachefly.net/100mb.test -O 100mb.test && rm -fr 100mb.test
}
configure_aria2() {
if which aria2c >/dev/null; then
print_warn "Aria2 is already installed."
exit 1
fi
check_install nginx 1 "nginx is already installed. Please remove it before installing Aria2."
print_info "Enter a secret token"
read -s secret
print_info "Enter a port for the Aria2 Daemon"
read aport
php=n
db=n
db1=n
install_webserver
print_info "Installing Aria2 (This might take some time, please be patient...)"
file="/etc/apt/sources.list.d/debian-testing.list"
if [ ! -f "$file" ]
then
touch /etc/apt/sources.list.d/debian-testing.list
echo "deb http://http.us.debian.org/debian testing main non-free contrib" >>/etc/apt/sources.list.d/debian-testing.list
echo "deb-src http://http.us.debian.org/debian testing main non-free contrib" >>/etc/apt/sources.list.d/debian-testing.list
apt-get update &> /dev/null
wait
fi
DEBIAN_FRONTEND=noninteractive apt-get install aria2 git curl -y &> /dev/null
wait
rm /etc/apt/sources.list.d/debian-testing.list
apt-get update &> /dev/null
wait
mkdir /usr/share/aria2
mkdir /usr/share/Downloads
mkdir /var/log/aria2/
touch /var/log/aria2/aria2.log
touch /usr/share/aria2/aria2.conf
touch /usr/share/aria2/input.txt
/bin/cat <<"EOM" >/usr/share/aria2/aria2.conf
dir=/usr/share/Downloads
file-allocation=none
continue
log-level=warn
check-certificate=false
max-connection-per-server=8
summary-interval=120
daemon=true
enable-rpc=true
enable-dht=true
rpc-listen-port=
rpc-listen-all=true
max-concurrent-downloads=3
http-auth-challenge=true
input-file=/usr/share/aria2/input.txt
log=/var/log/aria2/aria2.log
disable-ipv6=false
disk-cache=25M
timeout=600
retry-wait=30
max-tries=50
EOM
sed -i "s|rpc-listen-port=|rpc-listen-port=$aport|" /usr/share/aria2/aria2.conf
touch /etc/init.d/aria2
/bin/cat <<"EOM" >/etc/init.d/aria2
#! /bin/sh
# /etc/init.d/aria2
### BEGIN INIT INFO
# Provides: aria2cRPC
# Required-Start: $network $local_fs $remote_fs
# Required-Stop: $network $local_fs $remote_fs
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: aria2c RPC init script.
# Description: Starts and stops aria2 RPC services.
### END INIT INFO
RETVAL=0
case "$1" in
start)
echo -n "Starting aria2c daemon: "
umask 0000
aria2c --daemon=true --enable-rpc --rpc-listen-all --rpc-secret=secret -D --conf-path=/usr/share/aria2/aria2.conf
umask 0000
aria2c --daemon=true --enable-rpc --rpc-listen-all --rpc-secret=secret -D --conf-path=/usr/share/aria2/aria2.conf
RETVAL=$?
echo
;;
stop)
echo -n "Shutting down aria2c daemon: "
/usr/bin/killall aria2c
RETVAL=$?
echo
;;
restart)
stop
sleep 3
start
;;
*)
echo $"Usage: $0 {start|stop|restart}"
RETVAL=1
esac
exit $RETVAL
EOM
sed -i "s|.*aria2c --daemon=true --enable-rpc --rpc-listen-all --rpc-secret=secret.*|aria2c --daemon=true --enable-rpc --rpc-listen-all --rpc-secret=$secret -D --conf-path=/usr/share/aria2/aria2.conf|" /etc/init.d/aria2
chmod +x /etc/init.d/aria2
update-rc.d aria2 defaults &> /dev/null
git clone https://github.com/ziahamza/webui-aria2.git /usr/share/nginx/html/aria2 &> /dev/null
wait
if which ufw >/dev/null; then
ufw allow "$aport"/tcp &> /dev/null
ufw allow 80/tcp &> /dev/null
ufw disable &> /dev/null
ufw --force enable &> /dev/null
fi
service aria2 start &> /dev/null
wait
rm -rf /tmp/aria2
if [[ $ssl = "y" ]]
then
if [[ $sslv = "1" ]]
then
sed -i "s|.*aria2c --daemon=true --enable-rpc --rpc-listen-all --rpc-secret.*|aria2c --daemon=true --enable-rpc --rpc-certificate=/etc/nginx/ssl/nginx.crt --rpc-private-key=/etc/nginx/ssl/nginx.key --rpc-secure=true --rpc-listen-all --rpc-secret=$secret -D --conf-path=/usr/share/aria2/aria2.conf|" /etc/init.d/aria2
elif [[ $sslv = "2" ]]
then
sed -i "s|.*aria2c --daemon=true --enable-rpc --rpc-listen-all --rpc-secret.*|aria2c --daemon=true --enable-rpc --rpc-certificate=/etc/letsencrypt/live/"$d"/fullchain.pem --rpc-private-key=/etc/letsencrypt/live/"$d"/privkey.pem --rpc-secure=true --rpc-listen-all --rpc-secret=$secret -D --conf-path=/usr/share/aria2/aria2.conf|" /etc/init.d/aria2
fi
if which ufw >/dev/null; then
ufw allow "$aport"/tcp &> /dev/null
ufw allow 80/tcp &> /dev/null
ufw allow 443/tcp &> /dev/null
ufw disable &> /dev/null
ufw --force enable &> /dev/null
fi
sed -i "s|.*port: uri.port(),|      port: $aport,|" /usr/share/nginx/html/aria2/js/services/rpc/rpc.js
sed -i "s|.*port: 6800,|      port: $aport,|" /usr/share/nginx/html/aria2/js/services/rpc/rpc.js
systemctl daemon-reload
service aria2 stop
sleep 3
service aria2 start
fi
print_done "Aria2 has been installed"
print_done "Access it at http://$d/aria2"
print_done "Your secret token is $secret"
}
function get_linuxdash {
check_install nginx 0 "Please install nginx first."
if [[ ! -f /usr/sbin/php5-fpm ]] && [[ ! -f /usr/sbin/php-fpm7.0 ]] && [[ ! -f /usr/bin/hhvm ]]; then
 print_warn "PHP or HHVM is not installed."
exit 1
fi
apt-get install git curl -y
mkdir /usr/share/nginx/html/monitor
git clone https://github.com/afaqurk/linux-dash /usr/share/nginx/html/monitor
print_done "You can view the monitor at http://$(get_external_ip)/monitor"
}
function run_speedtest {
file="/home/speedtest-cli"
if [ ! -f "$file" ]
then
print_info "Fetching script"
apt-get install python -y &> /dev/null
wget -O /home/speedtest-cli https://raw.github.com/sivel/speedtest-cli/master/speedtest_cli.py --no-check-certificate
python /home/speedtest-cli --share
else
python /home/speedtest-cli  --share
fi
}
install_softether() {
check_install softether 1 "SoftEtherVPN is already installed" v
print_info "Running pre checks, this might take a while..."
apt-get update &> /dev/null
apt-get --purge remove -y bind9* &> /dev/null
apt-get install build-essential dnsmasq -y &> /dev/null
mkdir /tmp/softether
print_info "Downloading and installing SoftEther VPN Server...."
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
wget -O /tmp/softether/softether-vpnserver_x64.tar.gz http://www.softether-download.com/files/softether/v4.19-9599-beta-2015.10.19-tree/Linux/SoftEther_VPN_Server/64bit_-_Intel_x64_or_AMD64/softether-vpnserver-v4.19-9599-beta-2015.10.19-linux-x64-64bit.tar.gz &> /dev/null
wait
cd /tmp/softether
tar zxf softether-vpnserver_x64.tar.gz
wait
else
wget -O /tmp/softether/softether-vpnserver_x86.tar.gz http://www.softether-download.com/files/softether/v4.19-9599-beta-2015.10.19-tree/Linux/SoftEther_VPN_Server/32bit_-_Intel_x86/softether-vpnserver-v4.19-9599-beta-2015.10.19-linux-x86-32bit.tar.gz &> /dev/null
wait
cd /tmp/softether
tar zxf softether-vpnserver_x86.tar.gz
wait
fi
cd vpnserver
echo "1
1
1
1
" | make &> /dev/null
cd ..
mv vpnserver /opt
cd /opt/vpnserver/
chmod 600 *
chmod 700 vpncmd
chmod 700 vpnserver
touch /etc/init.d/vpnserver
/bin/cat <<"EOM" >/etc/init.d/vpnserver
#!/bin/sh
### BEGIN INIT INFO
# Provides:          vpnserver
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start daemon at boot time
# Description:       Enable Softether by daemon.
### END INIT INFO
DAEMON=/opt/vpnserver/vpnserver
LOCK=/var/lock/subsys/vpnserver
TAP_ADDR=192.168.7.1

test -x $DAEMON || exit 0
case "$1" in
start)
$DAEMON start
touch $LOCK
sleep 1
/sbin/ifconfig tap_soft $TAP_ADDR
;;
stop)
$DAEMON stop
rm $LOCK
;;
restart)
$DAEMON stop
sleep 3
$DAEMON start
sleep 1
/sbin/ifconfig tap_soft $TAP_ADDR
;;
*)
echo "Usage: $0 {start|stop|restart}"
exit 1
esac
exit 0
EOM
chmod 755 /etc/init.d/vpnserver
if [ ! -d "/var/lock/subsys" ]; then
  mkdir /var/lock/subsys
fi
update-rc.d vpnserver defaults &> /dev/null
/etc/init.d/vpnserver start &> /dev/null
mkdir /tmp/.vpntemp
touch /tmp/.vpntemp/vpnsetup.in
CONFIG=/tmp/.vpntemp/vpnsetup.in
print_info "Please enter a softether admin password: "
read -s softadmin
print_info "Please enter a IPSEC Secret: "
read -s secret
print_info "Please enter a l2tp username: "
read username
print_info "Please enter a l2tp password: "
read -s pass
print_info "Enter a custom port: "
read port
print_info "Select method"
print_info "1) SecureNAT"
print_info "2) Local Bridge"
read -s -n1 method
if [[ $method = "2" ]] && [[ ! -e /dev/net/tun ]]; then
	print_warn "TUN/TAP is not available, using SecureNAT instead."
	method="1"
fi
if [[ $method = "2" ]] ; then
/bin/cat <<"EOM" >/tmp/.vpntemp/vpnsetup.in
ServerPasswordSet ADMINPASSWORD
HubCreate VPN /PASSWORD:
hubdelete default
Hub VPN
UserCreate USERNAME /GROUP:none /REALNAME:none /NOTE:none
UserPasswordSet USERNAME /PASSWORD:TESTPASS
BridgeCreate VPN /DEVICE:soft /TAP:yes
ipsecenable /L2TP:yes /L2TPRAW:yes /ETHERIP:yes /PSK:TESTSECRET /DEFAULTHUB:VPN
listenercreate PORT
listenercreate 1701
listenercreate 1723
listenercreate 4500
listenercreate 500
flush
exit
EOM
else
/bin/cat <<"EOM" >/tmp/.vpntemp/vpnsetup.in
ServerPasswordSet ADMINPASSWORD
HubCreate VPN /PASSWORD:
hubdelete default
Hub VPN
UserCreate USERNAME /GROUP:none /REALNAME:none /NOTE:none
UserPasswordSet USERNAME /PASSWORD:TESTPASS
SecureNatEnable
ipsecenable /L2TP:yes /L2TPRAW:yes /ETHERIP:yes /PSK:TESTSECRET /DEFAULTHUB:VPN
listenercreate PORT
listenercreate 1701
listenercreate 1723
listenercreate 4500
listenercreate 500
flush
exit
EOM
fi
print_info "Continuing installation..."
sed -i "s/ADMINPASSWORD/$softadmin/g" $CONFIG
sed -i "s/USERNAME/$username/g" $CONFIG
sed -i "s/TESTPASS/$pass/g" $CONFIG
sed -i "s/TESTSECRET/$secret/g" $CONFIG
sed -i "s/PORT/$port/g" $CONFIG
/opt/vpnserver/vpncmd localhost:443 /SERVER /IN:$CONFIG &> /dev/null
rm -r /tmp/.vpntemp/vpnsetup.in
if [[ $method = "2" ]] ; then
echo -en '\n' >> /etc/dnsmasq.conf
echo "interface=tap_soft" >> /etc/dnsmasq.conf
echo "dhcp-range=tap_soft,192.168.7.50,192.168.7.60,12h" >> /etc/dnsmasq.conf
echo "dhcp-option=tap_soft,3,192.168.7.1" >> /etc/dnsmasq.conf
sed -i "s|.*listen-address=.*|listen-address=$(get_ip)|" /etc/dnsmasq.conf
touch /etc/sysctl.d/ipv4_forwarding.conf
fi
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/ipv4_forwarding.conf
sysctl --system &> /dev/null
iptables -t nat -A POSTROUTING -s 192.168.7.0/24 -j SNAT --to-source $(get_ip)
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 992 -j ACCEPT
iptables -A INPUT -p tcp --dport 1194 -j ACCEPT
iptables -A INPUT -p udp --dport 1194 -j ACCEPT
iptables -A INPUT -p tcp --dport 5555 -j ACCEPT
iptables -A INPUT -p udp --dport 500 -j ACCEPT
iptables -A INPUT -p udp --dport 4500 -j ACCEPT
iptables -A INPUT -p tcp --dport 1701 -j ACCEPT
iptables -A INPUT -p udp --dport 1701 -j ACCEPT
iptables -A INPUT -p tcp --dport 1723 -j ACCEPT
iptables -A INPUT -p udp --dport 1723 -j ACCEPT
iptables -A INPUT -p udp --dport $port -j ACCEPT
iptables -A INPUT -p tcp --dport $port -j ACCEPT
if [[ $method = "2" ]] ; then
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
apt-get install iptables-persistent -y &> /dev/null
sed -i "s|.*#user=.*|user=root|" /etc/dnsmasq.conf
if which ufw >/dev/null; then
ufw allow "$port"/tcp &> /dev/null
ufw disable &> /dev/null
ufw --force enable &> /dev/null
fi
print_info "Restarting services..."
/etc/init.d/vpnserver restart &> /dev/null
/etc/init.d/dnsmasq restart &> /dev/null
else
print_info "Restarting services..."
/etc/init.d/vpnserver restart &> /dev/null
fi
rm -rf /tmp/softether
print_done "SoftEtherVPN has been installed"
print_done "Please see the wiki https://github.com/eunas/gotdeb/wiki/SoftEtherVPN"
print_done "For further information."
}
install_remotedesktop() {
check_install x2goserver 1 "X2Go Server is already installed." v
print_info "Install X2GO. Please wait ..."
apt-key adv --recv-keys --keyserver keys.gnupg.net E1F958385BFE2B6E
file="/etc/apt/sources.list.d/x2go.list"
if [ ! -f "$file" ]
then
touch /etc/apt/sources.list.d/x2go.list
fi
if [ $(plain_version) = "7" ]; then
echo "deb http://packages.x2go.org/debian wheezy main" >> /etc/apt/sources.list.d/x2go.list
echo "deb-src http://packages.x2go.org/debian wheezy main" >> /etc/apt/sources.list.d/x2go.list
elif [ $(plain_version) = "8" ]; then
echo "deb http://packages.x2go.org/debian jessie main" >> /etc/apt/sources.list.d/x2go.list
echo "deb-src http://packages.x2go.org/debian jessie main" >> /etc/apt/sources.list.d/x2go.list
fi
apt-get update  &> /dev/null
apt-get install x2go-keyring -y &> /dev/null
apt-get install xfce4 iceweasel -y &> /dev/null

apt-get install x2goserver* -y &> /dev/null
service x2goserver start &> /dev/null
print_done "Installation completed"
print_done "Remember to create a new user"
print_done "X2Go client can be downloaded from"
print_done "http://wiki.x2go.org/doku.php/download:start"
}
secure_system() {
install_fail2ban() {
while true; do
check_install fail2ban 1 "fail2ban is already installed." v
print_info "This will install fail2ban, change the ssh port,"
print_info "permit ssh root login and create a new user"
print_info "Are you sure you want to continue ? [y/n]"
read -n1 choice
case $choice in
y|Y|yes|Yes|YES)
print_info "Name for the new user:"
read u
mkdir -p "/home/$u"
chmod 750 /home/$u
useradd -d /home/$u $u
chown -R $u /home/$u
wait
passwd $u
print_info "Choose a new ssh port (Press enter to skip)"
read p
print_done "User $u added with home dir /home/$u"
print_info "Installing..."
apt-get update &> /dev/null
apt-get install fail2ban -y &> /dev/null
wait
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sed -i "s|.*PermitRootLogin yes.*|PermitRootLogin no|"  /etc/ssh/sshd_config
if [[ -n "$p" ]] ; then
sed -i "s|.*Port.*|Port $p|"  /etc/ssh/sshd_config
elif [[ -z "$p" ]] ; then
PORT=$(cat /etc/ssh/sshd_config | grep Port)
unset p
p=${PORT#*Port }
fi
if which ufw >/dev/null; then
ufw allow $p &> /dev/null
ufw disable &> /dev/null
ufw --force enable &> /dev/null
fi
print_info "Restarting services...."
service fail2ban restart &> /dev/null
wait
service ssh restart &> /dev/null
print_done "Install complete."
print_done "Please check that your new user can login with ssh before closing this session."
break
;;
n|N|no|No|NO)
break
;;
     *)
     echo "That is not a valid choice."
     ;;
esac
done
}
install_ufw() {
check_install ufw 1 "ufw  is already installed." v
print_info "Ufw will disable all incoming ports except for ssh"
print_info "Ports can be opened using ufw allow port-number"
sleep 3
print_info "Installing..."
apt-get update &> /dev/null
apt-get install ufw -y &> /dev/null
PORT=$(cat /etc/ssh/sshd_config | grep Port)
unset p
p=${PORT#*Port }
if [[ ! /proc/net/if_inet6 ]]
 then
ipv6=0
else
ipv6=1
fi
if [[ $ipv6 = "1" ]]
then
sed -i "s|IPV6=.*|IPV6=yes|" /etc/default/ufw
fi
ufw default deny incoming &> /dev/null
ufw default allow outgoing &> /dev/null
ufw allow "$p" &> /dev/null
ufw --force enable &> /dev/null
print_done "Install complete."
}
unattended_upgrades() {
print_info "Setting up Unattended Upgrades..."
if [ -f /etc/cron.daily/apt.disabled ]; then
    mv /etc/cron.daily/apt.disabled /etc/cron.daily/apt
fi
apt-get upgrade &> /dev/null
echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | debconf-set-selections &> /dev/null
apt-get install unattended-upgrades -y &> /dev/null
print_done "Your installation is now configured to automaticly install critical updates."
}
while true; do
print_info "Select an option"
print_info "1) Install fail2ban"
print_info "2) Install UFW"
print_info "3) Unattended Upgrades"
print_info "e) Exit"
read -n1 choice
case $choice in
1)
install_fail2ban
break
;;
2)
install_ufw
break
;;
3)
unattended_upgrades
break
;;
e|E)
break
;;
     *)
     print_warn "That is not a valid choice, try a number from 1 to 3."
     ;;
esac
done
}
plex_setup() {
ram=$(free | awk '/^Mem:/{print $2}')
if [[  "$ram" -lt "524288" ]] ; then
print_warn "It's not recommended to install plex on a server with less then 512 MB RAM. Are you sure you want to continue ? [y/n]"
read -n1 ram
else
plex_install
fi
if [[ $ram =~ [yY](es)* ]] ; then
plex_install
else
exit 1
fi
}
plex_install() {
print_info "Installing Plex media server ..."
wget http://shell.ninthgate.se/packages/shell-ninthgate-se-keyring.key &> /dev/null
apt-key add shell-ninthgate-se-keyring.key &> /dev/null
wait
rm shell-ninthgate-se-keyring.key
apt-get update &> /dev/null && apt-get install plexmediaserver -y  &> /dev/null
wait
wget --no-check-certificate -O /etc/init.d/plexmediaserver https://raw.githubusercontent.com/eunas/gotdeb/master/resources/plexmediaserver  &> /dev/null
wait
chmod +x /etc/init.d/plexmediaserver
update-rc.d plexmediaserver defaults &> /dev/null
if which ufw >/dev/null; then
ufw allow 32400/tcp &> /dev/null
ufw disable &> /dev/null
ufw --force enable &> /dev/null
fi
service plexmediaserver restart &> /dev/null
wait
print_done "Plex media server has been installed. You can access it at http://$(get_ip):32400/web To get access to the server settings please setup a VPN on the server and access it's localip using that."
}
function setup_observium {
while true; do
print_info "Choose what you want to install:"
print_info "1) Install Server"
print_info "2) Install Client"
print_info "e) Exit"
read -n1 choice
case $choice in
1)
install_observium_server
break
;;
2)
install_observium_client
break
;;
e|E)
break
;;
     *)
     echo "That is not a valid choice, try a number from 1 to 2."
     ;;
esac
done
}
function install_observium_server {
print_info "Select a database server"
print_info "1) MariaDB"
print_info "2) MySQL"
read -n 1 dbs
if [[ $dbs = "1" ]] ; then
db=y
db1=n
elif [[ $dbs = "2" ]] ; then
db=n
db1=y
fi
php=y
install_webserver
wait
rand=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)
u=observium
p=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1)
#EXPECTED_ARGS=3
#E_BADARGS=65
MYSQL=`which mysql`
Q1="CREATE DATABASE IF NOT EXISTS observium;"
Q2="GRANT USAGE ON *.* TO $u@localhost IDENTIFIED BY '$p';"
Q3="GRANT ALL PRIVILEGES ON observium.* TO $u@localhost;"
Q4="FLUSH PRIVILEGES;"
SQL="${Q1}${Q2}${Q3}${Q4}"
print_info "Installing observium..."
$MYSQL -uroot -p$dbpass -e "$SQL"
apt-get update &> /dev/null
rm /etc/nginx/conf.d/default.conf
wget -O /etc/nginx/conf.d/default.conf https://raw.githubusercontent.com/eunas/gotdeb/master/resources/default.conf --no-check-certificate &> /dev/null
if [[ -e /usr/sbin/php-fpm7.0 ]]; then
apt-get install php7.0-snmp php-pear snmp graphviz php7.0-json rrdtool fping imagemagick whois mtr-tiny nmap ipmitool python-mysqldb curl -y &> /dev/null
elif [[ -e /usr/sbin/php5-fpm ]] || [[ -e /usr/bin/hhvm ]] ; then
apt-get install php5-snmp php-pear snmp graphviz php5-json rrdtool fping imagemagick whois mtr-tiny nmap ipmitool python-mysqldb curl -y &> /dev/null
fi
if [[ $ssl = "y" ]]; then
rm /etc/nginx/conf.d/default.conf
wget -O /etc/nginx/conf.d/default.conf https://raw.githubusercontent.com/eunas/gotdeb/master/resources/observium-ssl.conf --no-check-certificate &> /dev/null
wait
if [ $sslv = "1" ] ; then
sed -i "s|        ssl_certificate /cert.crt;|        ssl_certificate /etc/nginx/ssl/nginx.crt;|" /etc/nginx/conf.d/default.conf
sed -i "s|        ssl_certificate_key /privkey.key;|        ssl_certificate_key /etc/nginx/ssl/nginx.key;|" /etc/nginx/conf.d/default.conf
sed -i "s|        ssl_dhparam /dhparams.pem;|        ssl_dhparam /etc/nginx/ssl/dhparams.pem;|" /etc/nginx/conf.d/default.conf
fi
if [ $sslv = "2" ] ; then
sed -i "s|        ssl_certificate /cert.crt;|        ssl_certificate /etc/letsencrypt/live/"$d"/fullchain.pem;|" /etc/nginx/conf.d/default.conf
sed -i "s|        ssl_certificate_key /privkey.key;|        ssl_certificate_key /etc/letsencrypt/live/"$d"/privkey.pem;|" /etc/nginx/conf.d/default.conf
sed -i "s|        ssl_dhparam /dhparams.pem;|        ssl_dhparam /etc/letsencrypt/dhparams.pem;|" /etc/nginx/conf.d/default.conf
fi
if [ $web = "1" ] ; then
sed -i "s|       listen        443 ssl http2;|       listen        443 ssl;|" /etc/nginx/conf.d/default.conf
fi
fi
if [[ $phpv = "1" ]] ; then
sed -i "s|.*fastcgi_pass unix:/var/run/php.sock;|        fastcgi_pass unix:/var/run/php5-fpm.sock;|" /etc/nginx/conf.d/default.conf
elif [[ $phpv = "2" ]] ; then
sed -i "s|.*fastcgi_pass unix:/var/run/php.sock;|        fastcgi_pass unix:/var/run/php/php7.0-fpm.sock;|" /etc/nginx/conf.d/default.conf
elif [[ $phpv = "3" ]] ; then
sed -i "s|.*fastcgi_pass unix:/var/run/php.sock;|        fastcgi_pass unix:/var/run/hhvm/hhvm.sock;|" /etc/nginx/conf.d/default.conf
fi
sed -i "s|        server_name domain www.domain;|        server_name "$d";|" /etc/nginx/conf.d/default.conf
sed -i "5s|.*root /usr/share/nginx/html;|        root /opt/observium/html;|" /etc/nginx/conf.d/default.conf
sed -i "16s|.*root /usr/share/nginx/html;|        root /opt/observium/html;|" /etc/nginx/conf.d/default.conf
mkdir -p /opt/observium && cd /opt
wget -P /opt/ http://www.observium.org/observium-community-latest.tar.gz &> /dev/null
tar zxvf /opt/observium-community-latest.tar.gz -C /opt &> /dev/null
cp /opt/observium/config.php.default /opt/observium/config.php
sed -i "s|USERNAME|"$u"|" /opt/observium/config.php
sed -i "s|PASSWORD|"$p"|" /opt/observium/config.php
mkdir -p /opt/observium/rrd
mkdir /opt/observium/logs
chown www-data:www-data /opt/observium/rrd
cd /opt/observium
randp=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1)
php /opt/observium/discovery.php -u &> /dev/null
php adduser.php admin "$randp" 10 &> /dev/null
touch /etc/cron.d/observium
service nginx restart &> /dev/null
echo "33  */6   * * *   root    /opt/observium/discovery.php -h all >> /dev/null 2>&1" >> /etc/cron.d/observium
echo "*/5 *     * * *   root    /opt/observium/discovery.php -h new >> /dev/null 2>&1" >> /etc/cron.d/observium
echo "*/5 *     * * *   root    /opt/observium/poller-wrapper.py 2 >> /dev/null 2>&1" >> /etc/cron.d/observium
print_done "---------------------------------------------------------------"
print_done "Observium has been installed. Login at http://$d"
print_done "Login details:"
print_done "Username: admin"
print_done "Password: $randp"
print_done "---------------------------------------------------------------"
print_done "Database details"
print_done "Database: observium"
print_done "Username: $u"
print_done "password: $p"
print_done "---------------------------------------------------------------"
print_warn "Write this information down now. It will NOT be stored."
print_done "---------------------------------------------------------------"
print_done ""
print_done ""
print_done ""
exit 1
}
function install_observium_client {
#!/bin/bash
print_info "Contact email"
read mail
print_info "Community"
read comm
print_info "Specify port (Leave blank for default)"
read port
if [ -z "$port" ] ; then
port="161"
fi
COMMUNITY=$comm
CONTACT=$mail
print_info "Please enter where the server is physically located:"
read loc
LOCATION=$loc
listen=$(hostname --ip-address)
print_info "Installing Observium client, please wait..."
apt-get update &> /dev/null
apt-get install -y snmpd &> /dev/null
sed -i.bak "/SNMPDOPTS=/c\SNMPDOPTS='-Lsd -Lf /dev/null -u snmp -p /var/run/snmpd.pid'" /etc/default/snmpd
cat > /etc/snmp/snmpd.conf <<END
com2sec readonly  default         $COMMUNITY
group MyROGroup v1         readonly
group MyROGroup v2c        readonly
group MyROGroup usm        readonly
agentaddress $listen:$port
view all    included  .1                               80
access MyROGroup ""      any       noauth    exact  all    none   none
syslocation $LOCATION
syscontact $CONTACT
#This line allows Observium to detect the host OS if the distro script is installed
extend .1.3.6.1.4.1.2021.7890.1 distro /usr/bin/distro
END
#get distro checking script
wget -O distro https://raw.githubusercontent.com/eunas/gotdeb/master/resources/observium_distro --no-check-certificate &> /dev/null
mv distro /usr/bin/distro
chmod +x /usr/bin/distro
if which ufw >/dev/null; then
ufw allow "$port"/tcp &> /dev/null
ufw disable &> /dev/null
ufw --force enable &> /dev/null
fi
/etc/init.d/snmpd restart &> /dev/null
print_done "#########################################################"
print_done "##           !! !! Installation Complete !! !!         ##"
print_done "#########################################################"
print_done "#You may add this server to your Observium installation #"
print_done "#          using $COMMUNITY as the Community            #"
print_done "#########################################################"
print_done "##         Install Script by www.SonicBoxes.com        ##"
print_done "##              Modified by eunas.net                  ##"
print_done "#########################################################"
}
function install_transmission {
check_install transmission-daemon 1 "Transmission is already installed" v
print_info "Please enter a username: "
read transu
print_info "Please enter a password: "
read -s transp
print_info "Please enter port (Leave blank to use default)"
read trp
if [ -z "$trp" ] ; then
trp="9091"
fi
print_info "Installing  Transmission BitTorrent client, please wait..."
apt-get install transmission-daemon -y  &> /dev/null
wait
mkdir /usr/share/transmission/completed /usr/share/transmission/incomplete
chown debian-transmission:debian-transmission /usr/share/transmission/completed
chown debian-transmission:debian-transmission /usr/share/transmission/incomplete
if ! id -u "$transu" >/dev/null 2>&1; then
useradd -d /home/$transu $transu
wait
echo "$transu:$transp" | chpasswd
mkdir -p "/home/$transu"
chmod 750 /home/$transu
chown -R $transu /home/$transu
fi
usermod -a -G debian-transmission $transu
chmod 775 /usr/share/transmission/*
service transmission-daemon stop &> /dev/null
wait
sed -i "s|.*download-dir.*|    \"download-dir\": \"/usr/share/transmission/completed\",|" /etc/transmission-daemon/settings.json
sed -i "s|\"incomplete-dir\": \"/var/lib/transmission-daemon/Downloads\",|\"incomplete-dir\": \"/usr/share/transmission/incomplete\",|" /etc/transmission-daemon/settings.json
sed -i "s|.*rpc-password.*|    \"rpc-password\": \"$transp\",|" /etc/transmission-daemon/settings.json
sed -i "s|.*rpc-port.*|    \"rpc-port\": $trp,|" /etc/transmission-daemon/settings.json
sed -i "s|.*rpc-bind-address.*|    \"rpc-bind-address\": \"$(get_ip)\",|" /etc/transmission-daemon/settings.json
sed -i "s|.*rpc-username.*|    \"rpc-username\": \"$transu\",|" /etc/transmission-daemon/settings.json
sed -i "s|\"rpc-whitelist\": \"127.0.0.1\",|\"rpc-whitelist\": \"127.0.0.1,*.*.*.*\",|" /etc/transmission-daemon/settings.json
if which ufw >/dev/null; then
ufw allow "$trp"/tcp &> /dev/null
ufw disable &> /dev/null
ufw --force enable &> /dev/null
fi
service transmission-daemon start &> /dev/null
wait
clear
print_info ""
print_info "----------------------------------------------------"
print_info "Transmissions has been installed."
print_info ""
print_info "Navigate to http://$(get_external_ip):$trp"
print_info "Login with username: $transu and the"
print_info "password you selected during installation."
print_info ""
print_info "----------------------------------------------------"
print_info ""
}
function install_blog {
while true; do
print_info "Choose a blog to install:"
print_info "1) Ghost"
print_info "2) Wordpress"
print_info "e) Exit"
read -n 1 choice
case $choice in
1)
install_ghost
break
;;
2)
install_wp
break
;;
e|E)
break
;;
     *)
     print_warn "That is not a valid choice."
     ;;
esac
done
}
install_ghost() {
check_install nginx 1 "nginx is already installed. Please remove it before installing ghost."
print_info "========================================================================="
print_info "Please notice that installing ghost on a lowend system can take 30+ min."
print_info "Your current nginx configuration will be overwritten"
print_info "========================================================================="
print_info ""
print_info "Enter port (Leave blank to use default)"
read gp
clear
print_info "Select a database server"
print_info "1) SQLite"
print_info "2) MariaDB"
print_info "3) MySQL"
read -n 1 dbs
    if [[ $dbs = "2" ]] || [[ $dbs = "3" ]] ; then
clear
print_info "Install PHP ? [y/n]"
read -n 1 pha
fi
if [[ $pha != [YyNn] ]];
    then
    clear
    print_warn "Error in input, try again"
    exit 1
    fi
if [[ $pha = "y" ]] ; then
php=y
else
php=n
fi
if [[ $dbs = "2" ]] ; then
db=y
db1=n
elif [[ $dbs = "3" ]] ; then
db=n
db1=y
else
db=n
db1=n
fi
install_webserver
if [ -z "$gp" ] ; then
gp="2368"
fi
clear
print_info "Installing ghost. Please wait ...."
apt-get update  &> /dev/null
wait
apt-get install zip curl -y  &> /dev/null
wait

curl -sL https://deb.nodesource.com/setup_4.x | bash - &> /dev/null
apt-get install --yes nodejs &> /dev/null

wget -O /tmp/ghost.zip https://ghost.org/zip/ghost-latest.zip &> /dev/null
wait
mkdir -p /usr/share/ghost
unzip /tmp/ghost.zip -d /usr/share/ghost &> /dev/null
wait
cd /usr/share/ghost
npm install --production
wait
cp config.example.js config.js
wget -O /etc/nginx/conf.d/ghost.conf https://raw.githubusercontent.com/eunas/gotdeb/master/resources/ghost.conf --no-check-certificate  &> /dev/null
wait
mv /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default-backup
if [[  ssl = "y" ]]; then
if [ $sslv = "1" ] ; then
sed -i "s|    ssl_dhparam|    ssl_dhparam /etc/nginx/ssl/dhparams.pem;|" /etc/nginx/conf.d/ghost.conf
fi
if [ $sslv = "2" ] ; then
sed -i "s|    ssl_certificate /etc/nginx/ssl/nginx.crt;|    ssl_certificate /etc/letsencrypt/live/"$d"/fullchain.pem;|" /etc/nginx/conf.d/ghost.conf
sed -i "s|    ssl_certificate_key /etc/nginx/ssl/nginx.key;|    ssl_certificate_key /etc/letsencrypt/live/"$d"/privkey.pem;|" /etc/nginx/conf.d/ghost.conf
sed -i "s|    ssl_dhparam|    ssl_dhparam /etc/letsencrypt/dhparams.pem;|" /etc/nginx/conf.d/ghost.conf
fi
if [ $web = "1" ] ; then
sed -i "s|    listen 443 ssl http2;|    listen 443 ssl;|" /etc/nginx/conf.d/ghost.conf
fi
fi
if [[ $phpv = "2" ]] ; then
sed -i "s|.*fastcgi_pass unix:/var/run/php5-fpm.sock;|fastcgi_pass unix:/var/run/php/php7.0-fpm.sock;|" /etc/nginx/conf.d/ghost.conf
elif [[ $phpv = "3" ]] ; then
sed -i "s|        fastcgi_pass unix:/var/run/php5-fpm.sock;|        fastcgi_pass unix:/var/run/hhvm/hhvm.sock;|" /etc/nginx/conf.d/ghost.conf
fi
if [[ $dbs = "2" ]] || [[ $dbs = "3" ]] ; then
rand=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)
u=ghost_$rand
p=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1)
#EXPECTED_ARGS=3
#E_BADARGS=65
MYSQL=`which mysql`
Q1="CREATE DATABASE IF NOT EXISTS ghost;"
Q2="GRANT USAGE ON *.* TO $u@localhost IDENTIFIED BY '$p';"
Q3="GRANT ALL PRIVILEGES ON ghost.* TO $u@localhost;"
Q4="FLUSH PRIVILEGES;"
SQL="${Q1}${Q2}${Q3}${Q4}"
$MYSQL -uroot -p$dbpass -e "$SQL"
sed -i "s|            client: 'sqlite3',|            client: 'mysql',|" /usr/share/ghost/config.js
sed -i "s|filename: path.join(__dirname, '/content/data/ghost.db')|host: 'localhost',\n                user: '"$u"',\n                password: '"$p"',\n                database: 'ghost',\n                charset: 'utf8'|" /usr/share/ghost/config.js
fi
sed -i "s|.*http://my-ghost-blog.com.*|        url: 'http://$d',|" /usr/share/ghost/config.js
sed -i "s|            host: '127.0.0.1',|            host: '0.0.0.0',|" /usr/share/ghost/config.js
sed -i "s|            port: '2368'|            port: '"$gp"'|" /usr/share/ghost/config.js
sed -i "s|    server_name server_name;|    server_name "$d";|" /etc/nginx/conf.d/ghost.conf
sed -i "s|proxy_pass http://127.0.0.1:2368;|proxy_pass http://127.0.0.1:"$gp";|" /etc/nginx/conf.d/ghost.conf
useradd -r ghost -U
chown -R ghost:ghost /usr/share/ghost
wget -O /etc/init.d/ghost https://raw.github.com/TryGhost/Ghost-Config/master/init.d/ghost  &> /dev/null
sed -i "s|GHOST_ROOT=/var/www/ghost|GHOST_ROOT=/usr/share/ghost|" /etc/init.d/ghost
chmod 755 /etc/init.d/ghost
update-rc.d ghost defaults  &> /dev/null
update-rc.d ghost enable  &> /dev/null
/etc/init.d/ghost start  &> /dev/null
service nginx restart  &> /dev/null
clear
print_done "======================================================"
print_done "Ghost has been installed"
print_done "You can access it at $d"
print_done "Access the admin area at $d/ghost"
if [[ $dbs = "2" ]] || [[ $dbs = "3" ]] ; then
print_done ""
print_done "Database information:"
print_done "Username: $u"
print_done "Password: $p"
fi
print_done "======================================================"
}
install_wp() {
check_install nginx 1 "nginx is already installed. Please remove it before installing Wordpress."
php=y
db=y
db1=n
install_webserver
rand=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)
u=wordpress_$rand
p=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1)
while ! mysql -u root -p$dbpass  -e 2>/dev/null ";" ; do
       read -s -p "Can't connect, please retry: " dbpass
done
print_info "Installing Wordpress..."
#EXPECTED_ARGS=3
#E_BADARGS=65
MYSQL=`which mysql`
Q1="CREATE DATABASE IF NOT EXISTS wordpress;"
Q2="GRANT USAGE ON *.* TO $u@localhost IDENTIFIED BY '$p';"
Q3="GRANT ALL PRIVILEGES ON wordpress.* TO $u@localhost;"
Q4="FLUSH PRIVILEGES;"
SQL="${Q1}${Q2}${Q3}${Q4}"
$MYSQL -uroot -p$dbpass -e "$SQL"
wget -O /tmp/wordpress.tar.gz http://wordpress.org/latest.tar.gz  &> /dev/null
wait
tar -C /tmp/ -xvzf /tmp/wordpress.tar.gz  &> /dev/null
wait
cp -r /tmp/wordpress/* /usr/share/nginx/html/  &> /dev/null
wait
cp /usr/share/nginx/html/wp-config-sample.php /usr/share/nginx/html/wp-config.php  &> /dev/null
wget -O /tmp/wp.keys https://api.wordpress.org/secret-key/1.1/salt/ &> /dev/null
sed -i '/#@-/r /tmp/wp.keys' /usr/share/nginx/html/wp-config.php
sed -i "/#@+/,/#@-/d" /usr/share/nginx/html/wp-config.php
sed -i "s/database_name_here/wordpress/" /usr/share/nginx/html/wp-config.php
sed -i "s/username_here/$u/" /usr/share/nginx/html/wp-config.php
sed -i "s/password_here/$p/" /usr/share/nginx/html/wp-config.php
mkdir /usr/share/nginx/html/wp-content/uploads
chmod 775 /usr/share/nginx/html/wp-content/uploads
rm -rf /tmp/*
clear
print_done "======================================================"
print_done "Wordpress has been installed"
print_done "You can access it at $d"
print_done "Database user: $u"
print_done "Database password: $p"
print_done "======================================================"
}
############################################################
# Menu
############################################################
check_sanity
while true; do
print_info "Choose what you want to install:"
print_info "1) Nginx"
print_info "2) Blogs"
print_info "3) PHP"
print_info "4) MySQL Server"
print_info "5) MariaDB server"
print_info "6) phpMyAdmin"
print_info "7) PureFTPD"
print_info "8) OpenVPN Server"
print_info "9) SoftEther VPN"
print_info "10) Squid3 Proxy Server"
print_info "11) sSMTP server"
print_info "12) Aria2 + Webui"
print_info "13) Transmission"
print_info "14) X2Go + Xfce Desktop"
print_info "15) Plex Media Server"
print_info "16) Observium"
print_info "17) Linux-Dash"
print_info "18) User Management"
print_info "19) System Management"
print_info "20) About"
print_info "e) Exit"
read choice
case $choice in
1)
install_webserver
break
;;
2)
install_blog
break
;;
3)
php_version
break
;;
4)
install_mysql
break
;;
5)
install_mariadb
break
;;
6)
install_phpmyadmin
break
;;
7)
install_pureftpd
break
;;
8)
install_openvpn
break
;;
9)
install_softether
break
;;
10)
install_squid3
break
;;
11)
install_ssmtp
break
;;
12)
configure_aria2
break
;;
13)
install_transmission
break
;;
14)
install_remotedesktop
break
;;
15)
plex_setup
break
;;
16)
setup_observium
break
;;
17)
get_linuxdash
break
;;
18)
user_management
break
;;
19)
system_management
break
;;
20)
script_about
break
;;
e|E)
break
;;
     *)
     print_warn "That is not a valid choice, try a number from 1 to 20."
     ;;
esac
done