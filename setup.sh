#!/bin/bash
############################################################
# Core
############################################################
function check_sanity {
	# Do some sanity checking.
	if [ $(/usr/bin/id -u) != "0" ]
	then
		die 'Must be run by root user'
	fi

	if [ ! -f /etc/debian_version ]
	then
		die "Distribution is not supported"
	fi
}
function check_install {
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

function print_info {
	echo -n -e '\e[1;33m'
	echo -n $1
	echo -e '\e[0m'
}
function print_warn {
	echo -n -e '\e[1;31m'
	echo -n $1
	echo -e '\e[0m'
}
function print_done {
	echo -n -e '\e[1;32m'
	echo -n $1
	echo -e '\e[0m'
}
function die {
	echo "ERROR: $1" > /dev/null 1>&2
	exit 1
}
function get_ip {
IP=$(ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1)
echo "$IP"
}
function get_version {
version=$(dpkg -s $1 | grep 'Version')
print_info "$version"
}
function update_upgrade {
	# Run through the apt-get update/upgrade first.
	# This should be done before we try to install any package
	apt-get -q -y update
	apt-get -q -y upgrade

	# also remove the orphaned stuff
	apt-get -q -y autoremove
}
function dotdeb_repo {
if ! grep -q dotdeb "/etc/apt/sources.list"; then
sed -i '$a\deb http://packages.dotdeb.org wheezy-php56 all' /etc/apt/sources.list
sed -i '$a\deb-src http://packages.dotdeb.org wheezy-php56 all' /etc/apt/sources.list
sed -i '$a\deb http://packages.dotdeb.org wheezy all' /etc/apt/sources.list
sed -i '$a\deb-src http://packages.dotdeb.org wheezy all' /etc/apt/sources.list
wget http://www.dotdeb.org/dotdeb.gpg
apt-key add dotdeb.gpg
wait
rm dotdeb.gpg
apt-get update
wait
fi
}
function mariadb_repo {
if ! grep -q mariadb "/etc/apt/sources.list"; then
sed -i '$a\deb http://nyc2.mirrors.digitalocean.com/mariadb/repo/10.0/debian wheezy main' /etc/apt/sources.list
sed -i '$a\deb-src http://nyc2.mirrors.digitalocean.com/mariadb/repo/10.0/debian wheezy main' /etc/apt/sources.list
apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0xcbcb082a1bb943db
wait
add-apt-repository 'deb http://nyc2.mirrors.digitalocean.com/mariadb/repo/10.0/debian wheezy main'
wait
apt-get update
wait
fi
}
function mysql_opt {
mysql_secure_installation
sed -i '/skip-external-locking/ a\innodb=OFF' /etc/mysql/my.cnf
sed -i '/innodb=OFF/ a\default-storage-engine=MyISAM' /etc/mysql/my.cnf
sed -i '/default-storage-engine=MyISAM/ a\default-tmp-storage-engine=MyISAM' /etc/mysql/my.cnf
sed -i "s|.*default_storage_engine.*|#|" /etc/mysql/my.cnf
service mysql restart
}
############################################################
# Apps
############################################################
function install_nginx {
    dotdeb_repo
    check_install nginx 1 "ngninx is already installed" v
    DEBIAN_FRONTEND=noninteractive apt-get install -y nginx
    /bin/cat <<"EOM" >/etc/nginx/sites-available/default
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
}
EOM
cpu_count=`grep -c ^processor /proc/cpuinfo`
sed -i "s|.*worker_processes [0-9].*|worker_processes $cpu_count;|" /etc/nginx/nginx.conf
IP=$(ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1)
print_info "Enter Domain, leave blank to use IP"
read d
if [ -z "$d" ] ; then
d="$IP"
fi
sed -i "s|.*server_name.*|        server_name "$d";|" /etc/nginx/sites-available/default
service nginx restart
    print_done "ngninx successfully installed."
}
function install_php {
    dotdeb_repo
    check_install php5-fpm 1 "php5-fpm is already installed" v
    DEBIAN_FRONTEND=noninteractive apt-get install php5-fpm php5-common php5-mysql php5-sqlite php5-mcrypt php5-curl curl php5-cli php5-gd -y
    wait
    sed -i "s|.*cgi.fix_pathinfo.*|cgi.fix_pathinfo=0|" /etc/php5/fpm/php.ini
    sed -i "s|.*upload_max_filesize = 2M.*|upload_max_filesize = 128M|" /etc/php5/fpm/php.ini
    sed -i "s|.*post_max_size = 8M.*|post_max_size = 128M|" /etc/php5/fpm/php.ini
    sed -i "s|.*reload signal USR2.*|        #reload signal USR2|" /etc/init/php5-fpm.conf
    sed -i "s|.*# gzip_vary on.*|        gzip_vary on;|" /etc/nginx/nginx.conf
    sed -i "s|.*# gzip_proxied any.*|        gzip_proxied any;|" /etc/nginx/nginx.conf
    sed -i "s|.*# gzip_comp_level 6.*|        gzip_comp_level 6;|" /etc/nginx/nginx.conf
    sed -i "s|.*# gzip_buffers 16 8k.*|         gzip_buffers 16 8k;|" /etc/nginx/nginx.conf
    sed -i "s|.*# gzip_http_version 1.1.*|        gzip_http_version 1.1;|" /etc/nginx/nginx.conf
    sed -i "s|.*# gzip_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript.*|        gzip_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript;|" /etc/nginx/nginx.conf
    service php5-fpm start
    wait
    touch /usr/share/nginx/html/info.php
/bin/cat <<"EOM" >/usr/share/nginx/html/info.php
    <?php
    phpinfo();
    ?>
EOM
    print_done "PHP-FPM 5.6 successfully installed."
}
function install_mysql {
check_install mysql-server 1 "MySQL is already installed"
check_install mariadb-server 1 "MariaDB is the current DB server. Can't install MySQL"
apt-get update
wait
DEBIAN_FRONTEND=noninteractive apt-get  -y install mysql-server mysql-client
wait
mysql_opt
print_done "MySQL successfully installed."
}
function install_mariadb {
check_install mysql-server  1 "MySQL is the current DB server. Can't install Mariadb"
check_install mariadb-server 1 "MariaDB Server is already installed"
mariadb_repo
DEBIAN_FRONTEND=noninteractive apt-get -y install python-software-properties mariadb-server mariadb-client
wait
mysql_opt
print_done "MariaDB successfully installed."
}
function install_phpmyadmin {
check_install phpmyadmin 1 "phpMyAdmin is already installed" v
check_install nginx 0 "Please install a webserver first"
check_install php5-fpm 0 "phpMyAdmin requires php, please install it"
if ((! $(ps -ef | grep -v grep | grep mysql | wc -l) > 0 ))
then
        print_warn "The MySQL server is stopped or not installed.";
        exit 1

fi
echo "phpmyadmin phpmyadmin/reconfigure-webserver multiselect none" | debconf-set-selections
echo "phpmyadmin phpmyadmin/dbconfig-install boolean true" | debconf-set-selections
apt-get install phpmyadmin -y
wait
ln -s /usr/share/phpmyadmin/ /usr/share/nginx/html
print_done "phpMyAdmin successfully installed."
}
function install_pureftpd {
check_install pure-ftpd 1 "Pure-ftpd is already installed." v
apt-get update
wait
DEBIAN_FRONTEND=noninteractive apt-get install pure-ftpd -y
wait
print_info "Define port for Pure-ftpd, leave blank for port 21"
read p
if [ -z "$p" ] ; then
p="21"
fi
echo "yes" > /etc/pure-ftpd/conf/Daemonize
echo "yes" > /etc/pure-ftpd/conf/NoAnonymous
echo "yes" > /etc/pure-ftpd/conf/ChrootEveryone
echo "2" > /etc/pure-ftpd/conf/TLS
echo "$p" > /etc/pure-ftpd/conf/Bind
openssl req -x509 -nodes -days 7300 -newkey rsa:2048 -keyout /etc/ssl/private/pure-ftpd.pem -out /etc/ssl/private/pure-ftpd.pem -subj "/C=US/ST=defaultstate/L=defaultcity/O=myorg/CN=localhost"
service pure-ftpd restart
print_done "Pure-FTPd with FTPS support successfully installed."
}
function install_java {
check_install openjdk-7-jdk 1 "Java 7 JDK is already installed" v
apt-get -y install openjdk-7-jdk
print_done "Java 7 successfully installed."
}
function install_mcmyadmin {
check_install openjdk-7-jdk 0 "Please install Java"
print_info "Enter username for the user who should run the minecraft process"
read username
cuser=$(id -u $username)
if [ "" == "$cuser" ]; then
      print_warn "Please create the user first"
exit 1
fi
apt-get -y install unzip
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
print_done "-------------------------------------------------------------"
print_done "McMyAdmin installed in /home/$username/minecraft"
print_done "Run ./MCMA2_Linux_x86_64 -setpass YOURPASSWORD -configonly"
print_done "-------------------------------------------------------------"
}
function install_pptp {
print_info "######################################################"
print_info "Interactive PoPToP Install Script for an OpenVZ VPS"
print_info
print_info "Make sure to contact your provider and have them enable"
print_info "IPtables and ppp modules prior to setting up PoPToP."
print_info "PPP can also be enabled from SolusVM."
print_info
print_info "You need to set up the server before creating more users."
print_info "A separate user is required per connection or machine."
print_info "######################################################"
print_info
print_info
print_info "######################################################"
print_info "Select on option:"
print_info "1) Set up new PoPToP server AND create one user"
print_info "2) Create additional users"
print_info "######################################################"
read x
if test $x -eq 1; then
	print_info "Enter username that you want to create (eg. client1 or john):"
	read u
	print_info "Specify password that you want the server to use:"
	read p

# get the VPS IP
a="`netstat -i | cut -d' ' -f1 | grep eth0`";
b="`netstat -i | cut -d' ' -f1 | grep venet0:0`";

if [ "$a" == "eth0" ]; then
  ip="`/sbin/ifconfig eth0 | awk -F':| +' '/inet addr/{print $4}'`";
elif [ "$b" == "venet0:0" ]; then
  ip="`/sbin/ifconfig venet0:0 | awk -F':| +' '/inet addr/{print $4}'`";
fi

print_info
print_info "######################################################"
print_info "Downloading and Installing PoPToP"
print_info "######################################################"
apt-get update
apt-get -y install pptpd

print_info
print_info "######################################################"
print_info "Creating Server Config"
print_info "######################################################"
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

print_info
print_info "######################################################"
print_info "Forwarding IPv4 and Enabling it on boot"
print_info "######################################################"
cat >> /etc/sysctl.conf <<END
net.ipv4.ip_forward=1
END
sysctl -p

print_info
print_info "######################################################"
print_info "Updating IPtables Routing and Enabling it on boot"
print_info "######################################################"
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

print_info
print_info "######################################################"
print_info "Restarting PoPToP"
print_info "######################################################"
sleep 5
/etc/init.d/pptpd restart

print_done
print_done "######################################################"
print_done "Server setup complete!"
print_done "Connect to your VPS at $ip with these credentials:"
print_done "Username:$u ##### Password: $p"
print_done "######################################################"

# runs this if option 2 is selected
elif test $x -eq 2; then
	print_info "Enter username that you want to create (eg. client1 or john):"
	read u
	print_info "Specify password that you want the server to use:"
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
print_done "######################################################"
print_done "Addtional user added!"
print_done "Connect to your VPS at $ip with these credentials:"
print_done "Username:$u ##### Password: $p"
print_done "######################################################"

else
print_info "Invalid selection, quitting."
exit
fi
}
function install_openvpn {
if [[ ! -e /dev/net/tun ]]; then
	print_info "TUN/TAP is not available"
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
	print_info "Do you want OpenVPN to be available at port 53 too?"
	print_info "This can be useful to connect under restrictive networks"
	read -p "Listen at port 53 [y/n]: " -e -i n ALTPORT
	print_info ""
	print_info "Finally, tell me your name for the client cert"
	print_info "Please, use one word only, no special characters"
	read -p "Client name: " -e -i client CLIENT
	print_info ""
	print_info "Okay, that was all I needed. We are ready to setup your OpenVPN server now"
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
		print_info ""
		print_info "Looks like your server is behind a NAT!"
		print_info ""
		print_info "If your server is NATed (LowEndSpirit, NanoVZ), I need to know the external IP"
		print_info "If that's not the case, just ignore this and leave the next field blank"
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
	print_info ""
	print_done "Finished!"
	print_done ""
	print_done "Your client config is available at ~/ovpn-$CLIENT.tar.gz"
	print_done "If you want to add more clients, you simply need to run this script another time!"
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
print_info "Please enter a password (will be shown in plain text while typing):"
read p
print_info ""
print_info "Please enter the port squid3 will listen on:"
read sp
clear

a="`netstat -i | cut -d' ' -f1 | grep eth0`";
b="`netstat -i | cut -d' ' -f1 | grep venet0:0`";

if [ "$a" == "eth0" ]; then
  ip="`/sbin/ifconfig eth0 | awk -F':| +' '/inet addr/{print $4}'`";
elif [ "$b" == "venet0:0" ]; then
  ip="`/sbin/ifconfig venet0:0 | awk -F':| +' '/inet addr/{print $4}'`";
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get -y install apache2-utils squid3

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
http_port $sp

hierarchy_stoplist cgi-bin ?
coredump_dir /var/spool/squid3
cache deny all

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

htpasswd -b -c /etc/squid3/squid_passwd $u $p

service squid3 restart

clear

print_info ""
print_info "----------------------------------------------------"
print_info "Squid proxy server set up has been completed."
print_info ""
print_info "You can access your proxy server at $ip"
print_info "on port $sp with user name $u"
print_info ""
print_info "----------------------------------------------------"
print_info ""
}

function configure_ssmtp {
function install_ssmtp {
while true; do
print_info "Choose mail carrier:"
print_info "1) Mandrill"
print_info "2) Gmail"
print_info "e) Exit"
read choice
case $choice in
1)
print_info "specify email address"
read mmail
print_info "Server hostname"
read mhost
print_info "Your mandril login mail"
read mlogin
print_info "mandril api key"
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
sed -i "s|.*sendmail_path.*|sendmail_path = /usr/sbin/ssmtp -t|" /etc/php5/fpm/php.ini
print_done "ssmtp successfully configured."
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
sed -i "s|.*sendmail_path.*|sendmail_path = /usr/sbin/ssmtp -t|" /etc/php5/fpm/php.ini
print_done"ssmtp successfully configured."
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
while true; do
print_info "1) Install ssmpt"
print_info "2) Configure ssmtp"
print_info "e) Exit"
read choice
case $choice in
1)
    check_install ssmtp 1 "ssmtp already installed" v
    DEBIAN_FRONTEND=noninteractive apt-get install -y ssmtp
    print_done "ssmtp successfully installed."
break
;;
2)
install_ssmtp
break
;;
e)
break
;;
     *)
     print_warn "That is not a valid choice, try a number from 1 to 20."
     ;;
esac
done
}
function show_os_arch_version {
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
read choice
case $choice in
1)
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
2)
echo "Enter username"
read username
deluser $username
echo "User: $username deleted. Home directory is still intact"
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
function install_essentials {
while true; do
print_info "1) Remove unneeded packages and services"
print_info "2) Install essentials packages"
print_info "3) Update timezone"
print_info "e) Exit"
read choice
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
e)
break
;;
     *)
     print_warn "That is not a valid choice, try a number from 1 to 2."
     ;;
esac
done
}
function remove_unneeded {
	# Some Debian have portmap installed. We don't need that.
	apt-get --purge remove -y portmap

	# Other packages that are quite common in standard OpenVZ templates.
	apt-get --purge remove -y apache2*
	apt-get --purge remove -y bind9*
	apt-get --purge remove -y samba*
	apt-get --purge remove -y nscd
    sysv-rc-conf xinetd off
    sysv-rc-conf saslauthd off

	# Need to stop sendmail as removing the package does not seem to stop it.
	if [ -f /usr/lib/sm.bin/smtpd ]
	then
		invoke-rc.d sendmail stop
		apt-get --purge remove -y sendmail*
	fi
    print_done "You should restart now"
}
function essentials {
apt-get install -y nano rcconf lftp unzip
print_done "Essentials services installed"
}
function script_about {
print_info "Interactive essentials install script for VPS or Dedicated servers."
print_info "Build with low end systems in mind."
print_info "https://github.com/eunas/essentials"
print_info ""
print_info "Credits: Xeoncross, mikel, Falko Timme, road warrior and many more."
}
function system_tests {
	print_info "Classic I/O test"
	print_info "dd if=/dev/zero of=iotest bs=64k count=16k conv=fdatasync && rm -fr iotest"
	dd if=/dev/zero of=iotest bs=64k count=16k conv=fdatasync && rm -fr iotest

	print_info "Network test"
	print_info "wget cachefly.cachefly.net/100mb.test -O 100mb.test && rm -fr 100mb.test"
	wget cachefly.cachefly.net/100mb.test -O 100mb.test && rm -fr 100mb.test
}
function configure_aria2 {
if which aria2c >/dev/null; then
print_warn "Aria2 is already installed."
exit 1
fi
check_install nginx 0 "Please install nginx"
check_install php5-fpm 0 "Please install PHP"
IP=$(ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1)
apt-get install build-essential git autoconf dh-autoreconf libc-ares2 libc6 libgcc1 libgcrypt11 libgnutls26 libsqlite3-0 libstdc++6 libunwind7 libxml2 zlib1g libc-ares2 libcppunit-dev libxml2-dev libgcrypt11-dev pkg-config libgnutls-dev nettle-dev libc-ares-dev libsqlite3-dev libssl-dev sphinx-common -y
mkdir /tmp/aria2
git clone https://github.com/tatsuhiro-t/aria2.git /tmp/aria2
wait
cd /tmp/aria2
autoreconf -i
wait
./configure
wait
make
wait
make install
wait
make check
wait
mkdir /usr/share/aria2
mkdir /usr/share/Downloads
mkdir /var/log/aria2/
touch /var/log/aria2/aria2.log
touch /usr/share/aria2/aria2.conf
touch /usr/share/aria2/input.txt
/bin/cat <<"EOM" >/usr/share/aria2/aria2.conf
dir=/usr/share/Downloads
file-allocation=falloc
continue
log-level=warn
check-certificate=false
max-connection-per-server=8
summary-interval=120
daemon=true
enable-rpc=true
enable-dht=false
rpc-listen-port=6800
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
print_info "Enter a secret token"
read secret
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
sed -i "s|.*aria2c --daemon=true --enable-rpc --rpc-listen-all --rpc-secret=secret.*|aria2c --daemon=true --enable-rpc --rpc-listen-all --rpc-secret=$secret -D --conf-path=/usr/share/aria2/aria2.conf;|" /etc/init.d/aria2
chmod +x /etc/init.d/aria2
update-rc.d aria2 defaults
git clone https://github.com/ziahamza/webui-aria2.git /usr/share/nginx/html/aria2
service aria2 start
wait
rm -rf /tmp/aria2
print_done "Aria2 has been installed"
print_done "Access it at http://$(get_ip)/aria2"
print_done "Your secret token is $secret"
}
function get_linuxdash {
check_install nginx 0 "Please install nginx"
check_install php5-fpm 0 "Please install PHP"
apt-get install git -y
mkdir /usr/share/nginx/html/monitor
git clone https://github.com/afaqurk/linux-dash /usr/share/nginx/html/monitor
print_done "You can view the monitor at http://$(get_ip)/monitor"
}
function run_speedtest {
file="/home/speedtest-cli"
if [ ! -f "$file" ]
then
print_info "Fetching script"
apt-get install python -y
wget -O /home/speedtest-cli https://raw.github.com/sivel/speedtest-cli/master/speedtest_cli.py --no-check-certificate
python /home/speedtest-cli --share
else
python /home/speedtest-cli  --share
fi
}
function install_softether {
apt-get update
apt-get install build-essential dnsmasq -y
mkdir /tmp/softether
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
wget -O /tmp/softether/softether-vpnserver_x64.tar.gz http://www.softether-download.com/files/softether/v4.14-9529-beta-2015.02.02-tree/Linux/SoftEther_VPN_Server/64bit_-_Intel_x64_or_AMD64/softether-vpnserver-v4.14-9529-beta-2015.02.02-linux-x64-64bit.tar.gz
wait
cd /tmp/softether
tar zxf softether-vpnserver_x64.tar.gz
wait
else
wget -O /tmp/softether/softether-vpnserver_x86.tar.gz  http://www.softether-download.com/files/softether/v4.14-9529-beta-2015.02.02-tree/Linux/SoftEther_VPN_Server/32bit_-_Intel_x86/softether-vpnserver-v4.14-9529-beta-2015.02.02-linux-x86-32bit.tar.gz
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
" | make
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
mkdir /var/lock/subsys
update-rc.d vpnserver defaults
/etc/init.d/vpnserver start
mkdir /tmp/.vpntemp
touch /tmp/.vpntemp/vpnsetup.in
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
CONFIG=/tmp/.vpntemp/vpnsetup.in
echo "Please enter your softether admin password: "
read softadmin
echo "Please enter your IPSEC Secret: "
read secret
echo "Please enter your l2tp username: "
read username
echo "Please enter your l2tp password: "
read pass
echo "Enter a custom port: "
read port
sed -i "s/ADMINPASSWORD/$softadmin/g" $CONFIG
sed -i "s/USERNAME/$username/g" $CONFIG
sed -i "s/TESTPASS/$pass/g" $CONFIG
sed -i "s/TESTSECRET/$secret/g" $CONFIG
sed -i "s/PORT/$port/g" $CONFIG
/opt/vpnserver/vpncmd localhost:443 /SERVER /IN:$CONFIG
rm -r /tmp/.vpntemp/vpnsetup.in
echo "interface=tap_soft" >> /etc/dnsmasq.conf
echo "dhcp-range=tap_soft,192.168.7.50,192.168.7.60,12h" >> /etc/dnsmasq.conf
echo "dhcp-option=tap_soft,3,192.168.7.1" >> /etc/dnsmasq.conf
touch /etc/sysctl.d/ipv4_forwarding.conf
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/ipv4_forwarding.conf
sysctl --system
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
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
apt-get install iptables-persistent -y
/etc/init.d/vpnserver restart
/etc/init.d/dnsmasq restart
rm -rf /tmp/softether
}
############################################################
# Menu
############################################################
check_sanity
while true; do
print_info "Choose what you want to install:"
print_info "1) nginx 1.6.2"
print_info "2) PHP-FPM 5.6.5"
print_info "3) MySQL Server"
print_info "4) MariaDB server"
print_info "5) phpMyAdmin"
print_info "6) PureFTPD"
print_info "7) Java 7 JDK"
print_info "8) MCMyAdmin x64"
print_info "9) pptp server"
print_info "10) OpenVPN Server"
print_info "11) SoftEther VPN"
print_info "12) Squid3 Proxy Server"
print_info "13) sSMTP server"
print_info "14) Aria2 + Webui"
print_info "15) Linux-Dash"
print_info "16) Speedtest.net"
print_info "17) User Management"
print_info "18) Server Essentials"
print_info "19) Get OS Version"
print_info "20) System tests"
print_info "21) About"
print_info "e) Exit"
read choice
case $choice in
1)
install_nginx
break
;;
2)
install_php
break
;;
3)
install_mysql
break
;;
4)
install_mariadb
break
;;
5)
install_phpmyadmin
break
;;
6)
install_pureftpd
break
;;
7)
install_java
break
;;
8)
install_mcmyadmin
break
;;
9)
install_pptp
break
;;
10)
install_openvpn
break
;;
11)
install_softether
break
;;
12)
install_squid3
break
;;
13)
configure_ssmtp
break
;;
14)
configure_aria2
break
;;
15)
get_linuxdash
break
;;
16)
run_speedtest
break
;;
17)
user_management
break
;;
18)
install_essentials
break
;;
19)
show_os_arch_version
break
;;
20)
system_tests
break
;;
21)
script_about
break
;;
e)
break
;;
     *)
     echo "That is not a valid choice, try a number from 1 to 15."
     ;;
esac
done