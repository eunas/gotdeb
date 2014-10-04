#!/bin/bash
# Interactive essentials install script for VPS or Dedicated servers.
# https://github.com/eunas/essentials
if [ "$(id -u)" != "0" ]; then
  echo "This script must be run as root" 1>&2
  exit 1
fi
### Check if system is debian and version is meet
if [ ! -e /etc/debian_version ]; then
echo "Looks like you aren't running this installer on a Debian-based system"
exit
fi
required="7.0"
version=$(cat /etc/debian_version)
required=$(echo $required|sed 's/\.//g')
version=$(echo $version|sed 's/\.//g')
if [ $version -lt $required ]; then
echo "You need to run Debian 7.0 or higher"
exit 1
fi

while true; do
echo "Choose what you want to install:"
echo "1) Apache2 and PHP5"
echo "2) nginx and PHP5"
echo "3) MySQL Server and phpMyAdmin"
echo "4) MariaDB and phpMyAdmin"
echo "5) rcconf"
echo "6) vsftpd"
echo "7) Java 7 JDK"
echo "8) lftp"
echo "9) MCMyAdmin x64"
echo "10) pptp server"
echo "11) OpenVPN Server"
echo "12) Squid3 Proxy Server"
echo "13) Google Authenticator"
echo "14) sSMTP server"
echo "15) Add user"
echo "16) Delete user"
echo "17) User www dir"
echo "18) List users"
echo "19) Get OS Version"
echo "20) About"
echo "e) Exit"
read choice
case $choice in
1)
echo "Installing Apache2 and PHP5"
echo "Enter your admin email"
read e
if ! grep -q dotdeb "/etc/apt/sources.list"; then
sed -i '$a\deb http://packages.dotdeb.org wheezy-php56 all' /etc/apt/sources.list
sed -i '$a\deb-src http://packages.dotdeb.org wheezy-php56 all' /etc/apt/sources.list
wget http://www.dotdeb.org/dotdeb.gpg
wait
sudo apt-key add dotdeb.gpg
wait
fi
apt-get update -y
wait
apt-get -y install apache2
wait
apt-get -y install php5 libapache2-mod-php5 php5-mcrypt
wait
apt-get  -y install php5-mysql php5-curl php5-gd php5-idn php-pear php5-imagick php5-imap php5-memcache php5-pspell php5-recode php5-snmp php5-sqlite php5-tidy php5-xmlrpc php5-xsl
wait
a2enmod rewrite
wait
sed -i '11 s/AllowOverride None/AllowOverride All/' /etc/apache2/sites-enabled/000-default
sed -i 's/webmaster@localhost/'$e'/' /etc/apache2/sites-enabled/000-default
sed -i 's/webmaster@localhost/'$e'/' /etc/apache2/sites-available/default
sed -i 's/webmaster@localhost/'$e'/' /etc/apache2/sites-available/default-ssl 
wait
if grep -q dotdeb "/etc/apt/sources.list"; then
sed -i '/packages.dotdeb.org/d' /etc/apt/sources.list
wait
apt-get update
wait
a2enmod php5
fi
wait
/etc/init.d/apache2 restart
wait
echo "Apache2 and PHP5 installed. html root is /var/www"
touch /var/www/info.php
echo $'<?php\nphpinfo();\n?>' > /var/www/info.php
echo "Apache2 has been installed with PHP5 and mod_rewrite enabled ready to use"
echo "PHP5 modules compiled with apache2: php5-mysql php5-curl php5-gd php5-idn php-pear php5-imagick"
echo "php5-imap php5-mcrypt php5-memcache php5-pspell php5-recode php5-snmp"
echo "php5-sqlite php5-tidy php5-xmlrpc php5-xsl"
break
;;
2)
if [ $(dpkg-query -W -f='${Status}' nginx 2>/dev/null | grep -c "ok installed") -eq 1 ]; then
echo "nginx is already installed"
exit
fi
if [ $(dpkg-query -W -f='${Status}' apache2 2>/dev/null | grep -c "ok installed") -eq 1 ]; then
echo "Apache2 will be removed."
service apache2 stop
wait
apt-get remove apache2 -y
fi
if ! grep -q dotdeb "/etc/apt/sources.list"; then
sed -i '$a\deb http://packages.dotdeb.org wheezy all' /etc/apt/sources.list
sed -i '$a\deb-src http://packages.dotdeb.org wheezy all' /etc/apt/sources.list
wget http://www.dotdeb.org/dotdeb.gpg
wait
apt-key add dotdeb.gpg
wait
rm dotdeb.gpg
apt-get update
wait
apt-get install nginx -y
wait
fi
sed -i '/packages.dotdeb.org/d' /etc/apt/sources.list
wait
apt-get update
wait
apt-get install php5-fpm php5-common php5-mysql php5-cli php5-mcrypt php5-curl curl php5-gd php-apc -y
wait
sed -i "s|.*cgi.fix_pathinfo.*|cgi.fix_pathinfo=0|" /etc/php5/fpm/php.ini
/bin/cat <<"EOM" >/etc/nginx/sites-available/default
 server {
    listen 80 default_server;
    listen [::]:80 default_server ipv6only=on;

    root /usr/share/nginx/html;
    index index.php index.html index.htm;

    server_name

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
}
EOM
sed -i "s|.*# gzip_vary on.*|        gzip_vary on;|" /etc/nginx/nginx.conf
sed -i "s|.*# gzip_proxied any.*|        gzip_proxied any;|" /etc/nginx/nginx.conf
sed -i "s|.*# gzip_comp_level 6.*|        gzip_comp_level 6;|" /etc/nginx/nginx.conf
sed -i "s|.*# gzip_buffers 16 8k.*|         gzip_buffers 16 8k;|" /etc/nginx/nginx.conf
sed -i "s|.*# gzip_http_version 1.1.*|        gzip_http_version 1.1;|" /etc/nginx/nginx.conf
sed -i "s|.*# gzip_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript.*|        gzip_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript;|" /etc/nginx/nginx.conf
/bin/cat <<EOM >/etc/php5/fpm/conf.d/20-apc.ini
extension=apc.so

apc.enabled=1
apc.shm_size=128M
apc.ttl=3600
apc.user_ttl=7200
apc.gc_ttl=3600
apc.max_file_size=1M
EOM
IP=$(ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1)
sed -i "s|server_name|server_name "$IP";|" /etc/nginx/sites-available/default
service php5-fpm restart
service nginx restart
wait
touch /usr/share/nginx/html/info.php
echo $'<?php\nphpinfo();\n?>' > /usr/share/nginx/html/info.php
echo "nginx and php 5 installed"
break
;;
3)
if [ $(dpkg-query -W -f='${Status}' apache2 2>/dev/null | grep -c "ok installed") -eq 0 ]; then
      echo "Please install apache2 or nginx before mysql."
exit 1
fi
if [ $(dpkg-query -W -f='${Status}' nginx 2>/dev/null | grep -c "ok installed") -eq 0 ]; then
      echo "Please install apache2 or nginx before mysql."
exit 1
fi
if [ $(dpkg-query -W -f='${Status}' mariadb-server 2>/dev/null | grep -c "ok installed") -eq 1 ]; then
      echo "MariaDB already installed."
exit 1
fi
if [ $(dpkg-query -W -f='${Status}' mysql-server 2>/dev/null | grep -c "ok installed") -eq 0 ]; then
      echo "No MySQL. Installing....."
apt-get update
wait
apt-get -y install mysql-server mysql-client
wait
mysql_secure_installation
wait
if [ $(dpkg-query -W -f='${Status}' nginx 2>/dev/null | grep -c "ok installed") -eq 1 ]; then
echo "phpmyadmin phpmyadmin/reconfigure-webserver multiselect none" | debconf-set-selections
echo "phpmyadmin phpmyadmin/dbconfig-install boolean true" | debconf-set-selections
apt-get install phpmyadmin -y
wait
ln -s /usr/share/phpmyadmin/ /usr/share/nginx/html
service nginx restart
else
echo "phpmyadmin phpmyadmin/reconfigure-webserver multiselect apache2" | debconf-set-selections
echo "phpmyadmin phpmyadmin/dbconfig-install boolean true" | debconf-set-selections
apt-get install phpmyadmin -y
wait
sed -i '/skip-external-locking/ a\innodb=OFF' /etc/mysql/my.cnf
sed -i '/innodb=OFF/ a\default-storage-engine=MyISAM' /etc/mysql/my.cnf
wait
service mysql stop
wait
service mysql start
wait
echo "MySQL server and phpMyAdmin installed, default storage engine is MyISAM, InnoDB disabled."
fi
fi
break
;;
4)
if [ $(dpkg-query -W -f='${Status}' mariadb-server 2>/dev/null | grep -c "ok installed") -eq 1 ]; then
      echo "MariaDB already installed."
exit 1
fi
if [ $(dpkg-query -W -f='${Status}' mysql-server 2>/dev/null | grep -c "ok installed") -eq 1 ]; then
echo "MySQL will be removed."
service mysqld stop
wait
apt-get remove mysql-server -y
fi
if ! grep -q mariadb "/etc/apt/sources.list"; then
sed -i '$a\deb http://nyc2.mirrors.digitalocean.com/mariadb/repo/10.0/debian wheezy main' /etc/apt/sources.list
sed -i '$a\deb-src http://nyc2.mirrors.digitalocean.com/mariadb/repo/10.0/debian wheezy main' /etc/apt/sources.list
fi
apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0xcbcb082a1bb943db
wait
add-apt-repository 'deb http://nyc2.mirrors.digitalocean.com/mariadb/repo/10.0/debian wheezy main'
wait
apt-get update
wait
apt-get install python-software-properties -y
wait
apt-get install mariadb-server mariadb-client -y
wait
mysql_secure_installation
wait
if [ $(dpkg-query -W -f='${Status}' nginx 2>/dev/null | grep -c "ok installed") -eq 1 ]; then
echo "phpmyadmin phpmyadmin/reconfigure-webserver multiselect none" | debconf-set-selections
echo "phpmyadmin phpmyadmin/dbconfig-install boolean true" | debconf-set-selections
apt-get install phpmyadmin -y
wait
ln -s /usr/share/phpmyadmin/ /usr/share/nginx/html
service nginx restart
else
#echo PURGE | debconf-communicate packagename
echo "phpmyadmin phpmyadmin/reconfigure-webserver multiselect apache2" | debconf-set-selections
echo "phpmyadmin phpmyadmin/dbconfig-install boolean true" | debconf-set-selections
apt-get install phpmyadmin -y
fi
break
;;
5)
if [ $(dpkg-query -W -f='${Status}' rcconf 2>/dev/null | grep -c "ok installed") -eq 0 ]; then
      echo "No rcconf. Installing....."
      apt-get update
      wait
      apt-get --force-yes --yes install rcconf
wait
echo "rcconf installed"
fi
break
;;
6)
if [ $(dpkg-query -W -f='${Status}' vsftpd 2>/dev/null | grep -c "ok installed") -eq 0 ]; then
      echo "vsftpd is already installed. use apt-get --purge remove vsftpd to uninstall"
exit 1
fi
if [ "" == "$problem" ]; then
      echo "No vsftpd. Installing....."
apt-get -y install vsftpd python-software-properties
wait
apt-get update
wait
apt-get install vsftpd
wait
sed -i '$a\allow_writeable_chroot=YES' /etc/vsftpd.conf
sed -i 's/anonymous_enable=YES/#anonymous_enable=YES/' /etc/vsftpd.conf
sed -i 's/#local_enable=YES/local_enable=YES/' /etc/vsftpd.conf
sed -i 's/#data_connection_timeout=120/data_connection_timeout=120/' /etc/vsftpd.conf
sed -i 's/#idle_session_timeout=600/idle_session_timeout=600/' /etc/vsftpd.conf
sed -i 's/#local_umask=022/local_umask=022/' /etc/vsftpd.conf
sed -i 's/#write_enable=YES/write_enable=YES/' /etc/vsftpd.conf
sed -i '120 s/#chroot_local_user=YES/chroot_local_user=YES/' /etc/vsftpd.conf
sed -i '121 s/#chroot_list_enable=YES/chroot_list_enable=YES/' /etc/vsftpd.conf
sed -i '123 s/#//' /etc/vsftpd.conf
touch /etc/vsftpd.chroot_list
service vsftpd restart
echo "vsftpd installed, config file updated."
fi
break
;;
7)
apt-get -y install openjdk-7-jdk
break
;;
8)
apt-get -y install lftp
break
;;
9)
apt-get -y install unzip
echo "Enter username for the user who should run the minecraft process"
echo "Enter username"
read username
cuser=$(id -u $username)
if [ "" == "$cuser" ]; then
      echo "Please create the user first"
exit 1
fi
if [ ! -d "/home/$username/minecraft" ]; then
mkdir /home/$username/minecraft
fi
wget -P /home/$username/minecraft http://mcmyadmin.com/Downloads/MCMA2_glibc26_2.zip
wait
unzip -o /home/$username/minecraft/MCMA2_glibc26_2.zip -d /home/$username/minecraft
rm /home/$username/minecraft/MCMA2_glibc26_2.zip
wait
wget -P /tmp http://mcmyadmin.com/Downloads/etc.zip
wait
unzip -o /tmp/etc.zip -d /usr/local
wait
rm /tmp/etc.zip
chown -R $username /home/$username/minecraft
echo "McMyAdmin installed in /home/$username/minecraft"
echo "Run ./MCMA2_Linux_x86_64 -setpass YOURPASSWORD -configonly"
break
;;
10)
if [ $(dpkg-query -W -f='${Status}' pptpd 2>/dev/null | grep -c "ok installed") -eq 0 ]; then
      echo "pptpd is already installed. use apt-get --purge remove pptpd to uninstall"
exit 1
fi
if [ "" == "$problem" ]; then
      echo "pptpd not found. Installing....."
echo "######################################################"
echo "Interactive PoPToP Install Script for an OpenVZ VPS"
echo
echo "Make sure to contact your provider and have them enable"
echo "IPtables and ppp modules prior to setting up PoPToP."
echo "PPP can also be enabled from SolusVM."
echo
echo "You need to set up the server before creating more users."
echo "A separate user is required per connection or machine."
echo "######################################################"
echo
echo
echo "######################################################"
echo "Select on option:"
echo "1) Set up new PoPToP server AND create one user"
echo "2) Create additional users"
echo "######################################################"
read x
if test $x -eq 1; then
	echo "Enter username that you want to create (eg. client1 or john):"
	read u
	echo "Specify password that you want the server to use:"
	read p

# get the VPS IP
a="`netstat -i | cut -d' ' -f1 | grep eth0`";
b="`netstat -i | cut -d' ' -f1 | grep venet0:0`";

if [ "$a" == "eth0" ]; then
  ip="`/sbin/ifconfig eth0 | awk -F':| +' '/inet addr/{print $4}'`";
elif [ "$b" == "venet0:0" ]; then
  ip="`/sbin/ifconfig venet0:0 | awk -F':| +' '/inet addr/{print $4}'`";
fi

echo
echo "######################################################"
echo "Downloading and Installing PoPToP"
echo "######################################################"
apt-get update
apt-get -y install pptpd

echo
echo "######################################################"
echo "Creating Server Config"
echo "######################################################"
cat > /etc/ppp/pptpd-options <<END
name pptpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
ms-dns 8.8.8.8
ms-dns 8.8.4.4
proxyarp
nodefaultroute
lock
nobsdcomp
END

# setting up pptpd.conf
echo "option /etc/ppp/pptpd-options" > /etc/pptpd.conf
echo "logwtmp" >> /etc/pptpd.conf
echo "localip $ip" >> /etc/pptpd.conf
echo "remoteip 10.1.0.1-100" >> /etc/pptpd.conf

# adding new user
echo "$u	*	$p	*" >> /etc/ppp/chap-secrets

echo
echo "######################################################"
echo "Forwarding IPv4 and Enabling it on boot"
echo "######################################################"
cat >> /etc/sysctl.conf <<END
net.ipv4.ip_forward=1
END
sysctl -p

echo
echo "######################################################"
echo "Updating IPtables Routing and Enabling it on boot"
echo "######################################################"
iptables -t nat -A POSTROUTING -j SNAT --to $ip
# saves iptables routing rules and enables them on-boot
iptables-save > /etc/iptables.conf

cat > /etc/network/if-pre-up.d/iptables <<END
#!/bin/sh
iptables-restore < /etc/iptables.conf
END

chmod +x /etc/network/if-pre-up.d/iptables
cat >> /etc/ppp/ip-up <<END
ifconfig ppp0 mtu 1400
END

echo
echo "######################################################"
echo "Restarting PoPToP"
echo "######################################################"
sleep 5
/etc/init.d/pptpd restart

echo
echo "######################################################"
echo "Server setup complete!"
echo "Connect to your VPS at $ip with these credentials:"
echo "Username:$u ##### Password: $p"
echo "######################################################"

# runs this if option 2 is selected
elif test $x -eq 2; then
	echo "Enter username that you want to create (eg. client1 or john):"
	read u
	echo "Specify password that you want the server to use:"
	read p

# get the VPS IP
a="`netstat -i | cut -d' ' -f1 | grep eth0`";
b="`netstat -i | cut -d' ' -f1 | grep venet0:0`";

if [ "$a" == "eth0" ]; then
  ip="`/sbin/ifconfig eth0 | awk -F':| +' '/inet addr/{print $4}'`";
elif [ "$b" == "venet0:0" ]; then
  ip="`/sbin/ifconfig venet0:0 | awk -F':| +' '/inet addr/{print $4}'`";
fi

# adding new user
echo "$u	*	$p	*" >> /etc/ppp/chap-secrets

echo
echo "######################################################"
echo "Addtional user added!"
echo "Connect to your VPS at $ip with these credentials:"
echo "Username:$u ##### Password: $p"
echo "######################################################"

else
echo "Invalid selection, quitting."
exit
fi
fi
break
;;
11)
if [[ ! -e /dev/net/tun ]]; then
	echo "TUN/TAP is not available"
	exit
fi

# Try to get our IP from the system and fallback to the Internet.
# I do this to make the script compatible with NATed servers (lowendspirit.com)
# and to avoid getting an IPv6.
IP=$(ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1)
if [[ "$IP" = "" ]]; then
		IP=$(wget -qO- ipv4.icanhazip.com)
fi


if [[ -e /etc/openvpn/server.conf ]]; then
	while :
	do
	clear
		echo "Looks like OpenVPN is already installed"
		echo "What do you want to do?"
		echo ""
		echo "1) Add a cert for a new user"
		echo "2) Revoke existing user cert"
		echo "3) Remove OpenVPN"
		echo "4) Exit"
		echo ""
		read -p "Select an option [1-4]: " option
		case $option in
			1)
			echo ""
			echo "Tell me a name for the client cert"
			echo "Please, use one word only, no special characters"
			read -p "Client name: " -e -i client CLIENT
			cd /etc/openvpn/easy-rsa/2.0/
			source ./vars
			# build-key for the client
			export KEY_CN="$CLIENT"
			export EASY_RSA="${EASY_RSA:-.}"
			"$EASY_RSA/pkitool" $CLIENT
			# Let's generate the client config
			mkdir ~/ovpn-$CLIENT
			cp /usr/share/doc/openvpn/examples/sample-config-files/client.conf ~/ovpn-$CLIENT/$CLIENT.conf
			cp /etc/openvpn/easy-rsa/2.0/keys/ca.crt ~/ovpn-$CLIENT
			cp /etc/openvpn/easy-rsa/2.0/keys/$CLIENT.crt ~/ovpn-$CLIENT
			cp /etc/openvpn/easy-rsa/2.0/keys/$CLIENT.key ~/ovpn-$CLIENT
			cd ~/ovpn-$CLIENT
			sed -i "s|cert client.crt|cert $CLIENT.crt|" $CLIENT.conf
			sed -i "s|key client.key|key $CLIENT.key|" $CLIENT.conf
			tar -czf ../ovpn-$CLIENT.tar.gz $CLIENT.conf ca.crt $CLIENT.crt $CLIENT.key
			cd ~/
			rm -rf ovpn-$CLIENT
			echo ""
			echo "Client $CLIENT added, certs available at ~/ovpn-$CLIENT.tar.gz"
			exit
			;;
			2)
			echo ""
			echo "Tell me the existing client name"
			read -p "Client name: " -e -i client CLIENT
			cd /etc/openvpn/easy-rsa/2.0/
			. /etc/openvpn/easy-rsa/2.0/vars
			. /etc/openvpn/easy-rsa/2.0/revoke-full $CLIENT
			# If it's the first time revoking a cert, we need to add the crl-verify line
			if grep -q "crl-verify" "/etc/openvpn/server.conf"; then
				echo ""
				echo "Certificate for client $CLIENT revoked"
			else
				echo "crl-verify /etc/openvpn/easy-rsa/2.0/keys/crl.pem" >> "/etc/openvpn/server.conf"
				/etc/init.d/openvpn restart
				echo ""
				echo "Certificate for client $CLIENT revoked"
			fi
			exit
			;;
			3)
			apt-get remove --purge -y openvpn openvpn-blacklist
			rm -rf /etc/openvpn
			rm -rf /usr/share/doc/openvpn
			sed -i '/--dport 53 -j REDIRECT --to-port/d' /etc/rc.local
			sed -i '/iptables -t nat -A POSTROUTING -s 10.8.0.0/d' /etc/rc.local
			echo ""
			echo "OpenVPN removed!"
			exit
			;;
			4) exit;;
		esac
	done
else
	echo 'Welcome to this quick OpenVPN "road warrior" installer'
	echo ""
	# OpenVPN setup and first user creation
	echo "I need to ask you a few questions before starting the setup"
	echo "You can leave the default options and just press enter if you are ok with them"
	echo ""
	echo "First I need to know the IPv4 address of the network interface you want OpenVPN"
	echo "listening to."
	read -p "IP address: " -e -i $IP IP
	echo ""
	echo "What port do you want for OpenVPN?"
	read -p "Port: " -e -i 1194 PORT
	echo ""
	echo "Do you want OpenVPN to be available at port 53 too?"
	echo "This can be useful to connect under restrictive networks"
	read -p "Listen at port 53 [y/n]: " -e -i n ALTPORT
	echo ""
	echo "Finally, tell me your name for the client cert"
	echo "Please, use one word only, no special characters"
	read -p "Client name: " -e -i client CLIENT
	echo ""
	echo "Okay, that was all I needed. We are ready to setup your OpenVPN server now"
	read -n1 -r -p "Press any key to continue..."
	apt-get update
	apt-get install openvpn iptables openssl -y
	cp -R /usr/share/doc/openvpn/examples/easy-rsa/ /etc/openvpn
	# easy-rsa isn't available by default for Debian Jessie and newer
	if [[ ! -d /etc/openvpn/easy-rsa/2.0/ ]]; then
		wget --no-check-certificate -O ~/easy-rsa.tar.gz https://github.com/OpenVPN/easy-rsa/archive/2.2.2.tar.gz
		tar xzf ~/easy-rsa.tar.gz -C ~/
		mkdir -p /etc/openvpn/easy-rsa/2.0/
		cp ~/easy-rsa-2.2.2/easy-rsa/2.0/* /etc/openvpn/easy-rsa/2.0/
		rm -rf ~/easy-rsa-2.2.2
		rm -rf ~/easy-rsa.tar.gz
	fi
	cd /etc/openvpn/easy-rsa/2.0/
	# Let's fix one thing first...
	cp -u -p openssl-1.0.0.cnf openssl.cnf
	# Fuck you NSA - 1024 bits was the default for Debian Wheezy and older
	sed -i 's|export KEY_SIZE=1024|export KEY_SIZE=2048|' /etc/openvpn/easy-rsa/2.0/vars
	# Create the PKI
	. /etc/openvpn/easy-rsa/2.0/vars
	. /etc/openvpn/easy-rsa/2.0/clean-all
	# The following lines are from build-ca. I don't use that script directly
	# because it's interactive and we don't want that. Yes, this could break
	# the installation script if build-ca changes in the future.
	export EASY_RSA="${EASY_RSA:-.}"
	"$EASY_RSA/pkitool" --initca $*
	# Same as the last time, we are going to run build-key-server
	export EASY_RSA="${EASY_RSA:-.}"
	"$EASY_RSA/pkitool" --server server
	# Now the client keys. We need to set KEY_CN or the stupid pkitool will cry
	export KEY_CN="$CLIENT"
	export EASY_RSA="${EASY_RSA:-.}"
	"$EASY_RSA/pkitool" $CLIENT
	# DH params
	. /etc/openvpn/easy-rsa/2.0/build-dh
	# Let's configure the server
	cd /usr/share/doc/openvpn/examples/sample-config-files
	gunzip -d server.conf.gz
	cp server.conf /etc/openvpn/
	cd /etc/openvpn/easy-rsa/2.0/keys
	cp ca.crt ca.key dh2048.pem server.crt server.key /etc/openvpn
	cd /etc/openvpn/
	# Set the server configuration
	sed -i 's|dh dh1024.pem|dh dh2048.pem|' server.conf
	sed -i 's|;push "redirect-gateway def1 bypass-dhcp"|push "redirect-gateway def1 bypass-dhcp"|' server.conf
	sed -i "s|port 1194|port $PORT|" server.conf
	# Obtain the resolvers from resolv.conf and use them for OpenVPN
	grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
		sed -i "/;push \"dhcp-option DNS 208.67.220.220\"/a\push \"dhcp-option DNS $line\"" server.conf
	done
	# Listen at port 53 too if user wants that
	if [[ "$ALTPORT" = 'y' ]]; then
		iptables -t nat -A PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-port $PORT
		sed -i "/# By default this script does nothing./a\iptables -t nat -A PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-port $PORT" /etc/rc.local
	fi
	# Enable net.ipv4.ip_forward for the system
	sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf
	# Avoid an unneeded reboot
	echo 1 > /proc/sys/net/ipv4/ip_forward
	# Set iptables
	iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP
	sed -i "/# By default this script does nothing./a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP" /etc/rc.local
	# And finally, restart OpenVPN
	/etc/init.d/openvpn restart
	# Let's generate the client config
	mkdir ~/ovpn-$CLIENT
	# Try to detect a NATed connection and ask about it to potential LowEndSpirit
	# users
	EXTERNALIP=$(wget -qO- ipv4.icanhazip.com)
	if [[ "$IP" != "$EXTERNALIP" ]]; then
		echo ""
		echo "Looks like your server is behind a NAT!"
		echo ""
		echo "If your server is NATed (LowEndSpirit), I need to know the external IP"
		echo "If that's not the case, just ignore this and leave the next field blank"
		read -p "External IP: " -e USEREXTERNALIP
		if [[ "$USEREXTERNALIP" != "" ]]; then
			IP=$USEREXTERNALIP
		fi
	fi
	# IP/port set on the default client.conf so we can add further users
	# without asking for them
	sed -i "s|remote my-server-1 1194|remote $IP $PORT|" /usr/share/doc/openvpn/examples/sample-config-files/client.conf
	cp /usr/share/doc/openvpn/examples/sample-config-files/client.conf ~/ovpn-$CLIENT/$CLIENT.conf
	cp /etc/openvpn/easy-rsa/2.0/keys/ca.crt ~/ovpn-$CLIENT
	cp /etc/openvpn/easy-rsa/2.0/keys/$CLIENT.crt ~/ovpn-$CLIENT
	cp /etc/openvpn/easy-rsa/2.0/keys/$CLIENT.key ~/ovpn-$CLIENT
	cd ~/ovpn-$CLIENT
	sed -i "s|cert client.crt|cert $CLIENT.crt|" $CLIENT.conf
	sed -i "s|key client.key|key $CLIENT.key|" $CLIENT.conf
	tar -czf ../ovpn-$CLIENT.tar.gz $CLIENT.conf ca.crt $CLIENT.crt $CLIENT.key
	cd ~/
	rm -rf ovpn-$CLIENT
	echo ""
	echo "Finished!"
	echo ""
	echo "Your client config is available at ~/ovpn-$CLIENT.tar.gz"
	echo "If you want to add more clients, you simply need to run this script another time!"
fi
break
;;
12)
if [ $(dpkg-query -W -f='${Status}' squid3 2>/dev/null | grep -c "ok installed") -eq 0 ]; then
      echo "squid3 is already installed. use apt-get --purge remove squid3 to uninstall"
exit 1
fi
if [ "" == "$problem" ]; then
      echo "Squid3 not found. Installing....."
echo " "
echo "*****************************************************"
echo "WELCOME TO THE SQUID PROXY SERVER INSTALLATION SCRIPT"
echo "-----------------------------------------------------"
echo " "
echo " This script will set up a password protected, elite"
echo "             proxy on your target server"
echo " "
echo "*****************************************************"
echo " "
echo " "
echo "Please enter a user name for Squid:"
read u
echo " "
echo "Please enter a password (will be shown in plain text while typing):"
read p
echo " "

clear

a="`netstat -i | cut -d' ' -f1 | grep eth0`";
b="`netstat -i | cut -d' ' -f1 | grep venet0:0`";

if [ "$a" == "eth0" ]; then
  ip="`/sbin/ifconfig eth0 | awk -F':| +' '/inet addr/{print $4}'`";
elif [ "$b" == "venet0:0" ]; then
  ip="`/sbin/ifconfig venet0:0 | awk -F':| +' '/inet addr/{print $4}'`";
fi

apt-get update
apt-get -y install apache2-utils
apt-get -y install squid3

rm /etc/squid3/squid.conf

cat > /etc/squid3/squid.conf <<END
acl ip1 myip $ip
tcp_outgoing_address $ip ip1

auth_param basic program /usr/lib/squid3/ncsa_auth /etc/squid3/squid_passwd
acl ncsa_users proxy_auth REQUIRED
http_access allow ncsa_users

acl manager proto cache_object
acl localhost src 127.0.0.1/32
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32
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

http_access allow manager localhost
http_access deny manager
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access deny all
http_port 3128

hierarchy_stoplist cgi-bin ?
coredump_dir /var/spool/squid3
cache deny all

refresh_pattern ^ftp:        1440    20%    10080
refresh_pattern ^gopher:    1440    0%    1440
refresh_pattern -i (/cgi-bin/|\?) 0    0%    0
refresh_pattern .        0    20%    4320

icp_port 3130

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

htpasswd -b -c /etc/squid3/squid_passwd $u $p

service squid3 restart

clear

echo " "
echo "***************************************************"
echo "   Squid proxy server set up has been completed."
echo " "
echo "You can access your proxy server at $ip"
echo "on port 3128 with user name $u"
echo "Remember to change your name servers to 8.8.8.8 and 8.8.4.4 /etc/resolv.conf"
echo " "
echo "***************************************************"
echo " "
echo " "
fi
break
;;
13)
apt-get install libqrencode3
wait
wget http://ftp.us.debian.org/debian/pool/main/g/google-authenticator/libpam-google-authenticator_20130529-2_amd64.deb
wait
dpkg -i libpam-google-authenticator_20130529-2_amd64.deb
wait
sed -i '$a\auth required pam_google_authenticator.so' /etc/pam.d/sshd
sed -i 's/ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
/etc/init.d/ssh restart
echo " "
echo "***************************************************"
echo "   Google Authenticator."
echo " "
echo "Run google-authenticator"
echo "And remember to save the key before you logout."
echo "Else you will not be able to login again"
echo " "
echo "***************************************************"
echo " "
echo " "
break
;;
14)
if [ $(dpkg-query -W -f='${Status}' ssmtp 2>/dev/null | grep -c "ok installed") -eq 0 ];
then
apt-get update
wait
apt-get install ssmtp -y
wait
echo "Configure ssmtp now y/n ?"
read con
else
echo "ssmtp is already installed. Configure it now y/n ?"
read con
fi
if [ "$con" != "y" ]; then
echo "Exiting"
exit
fi
while true; do
echo "Choose mail carrier:"
echo "1) Mandrill"
echo "2) Gmail"
echo "e) Exit"
read choice
case $choice in
1)
echo "specify email address"
read mmail
echo "Server hostname"
read mhost
echo "Your mandril login mail"
read mlogin
echo "mandril api key"
read mapikey
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
/bin/cat <<EOM >/etc/ssmtp/revaliases
root:$mmail:smtp.mandrillapp.com:587
EOM
break
;;
2)
echo "specify email address"
read gmail
echo "Servers hostname"
read ghost
echo "Gmail address"
read glogin
echo "Gmail password"
read gapikey
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
/bin/cat <<EOM >/etc/ssmtp/revaliases
root:$gmail:smtp.gmail.com:587
EOM
if [ -f /etc/php5/apache2/php.ini ]; then
sed -i "s|.*sendmail_path.*|sendmail_path = /usr/sbin/ssmtp -t|" /etc/php5/apache2/php.ini
fi
if [ -f /etc/php5/fpm/php.ini ]; then
sed -i "s|.*sendmail_path.*|sendmail_path = /usr/sbin/ssmtp -t|" /etc/php5/fpm/php.ini
fi
break
;;
e)
break
;;
     *)
     echo "That is not a valid choice, try a number from 1 to 2."
     ;;
esac
done
break
;;
15)
echo "Enter username and password for the user you wish to create."
echo "Enter username"
read username
useradd -d /home/$username $username
wait
mkdir -p "/home/$username"
chmod 750 /home/$username
chown -R $username /home/$username
wait
passwd $username
echo "User $username added with home dir /home/$username"
break
;;
16)
echo "Enter username"
read username
deluser $username
echo "User: $username deleted. Home directory is still intact"
break
;;
17)
echo "Coming soon."
break
;;
18)
echo"------system users------"
cut -d: -f1 /etc/passwd
break
;;
19)
lsb_release -a
break
;;
20)
echo "Interactive essentials install script for VPS or Dedicated servers."
echo "Tested on Debian 7.5 +"
echo "https://github.com/eunas/essentials"
break
;;
e)
break
;;
     *)
     echo "That is not a valid choice, try a number from 1 to 20."
     ;;
esac
done