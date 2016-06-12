### 1.6.5 (2016-06-09)
- Updated LetsEncrypt to use Certbot.
- Updated LetsEncrypt autorenew
- Updated MySQL to version 5.7
- Fixed error in MariaDB repo
- Fixed standalone MariaDB installation.
- Various bug fixes

### 1.6.4 (2016-03-06)
- Fixed nginx config not being applied on setup
- Fixed error in nginx ssl redirect
- Added SSL support and port option for Aria2
- Added SSL Support for Observium
- Added UFW (Uncomplicated Firewall)
- Added Unattended Upgrades
- Updated OpenVPN installer
- Various bug fixes

### 1.6.3 (2016-02-02)
- Removed PPTP, Java and MCmyadmin install.
- Fixed PHP 5 detection
- Added SSL support for nginx with self signed certificate
- Added SSL support for Ghost Blog
- Added MySQL support for Ghost Blog
- Updated nodejs for Ghost
- Ghost and Wordpress are now installed with nginx.
- Other tweaks and fixes

### 1.6.2 (2016-01-17)
- Fixed errors in PHP 7 and PHP 5.6 install
- Added experimental [Let's Encrypt](https://github.com/eunas/gotdeb/wiki/lets-encrypt) support for nginx
- Updated MariaDB repo to version 10.1
- Other tweaks and fixes

### 1.6.1 (2016-01-10)
- Fixed typo in PHP 7 install.
- Fixed line break issue in Dnsmasq config
- Fetching the external IP correctly on NAT VPS servers
- Updated OpenVPN Installer.
- Updated Softether to version Ver 4.19 Build 9599 Beta

### 1.6 (2015-10-03)
- Added [HHVM](http://hhvm.com/) (64 bit OS support only)
- Added Dotdeb PHP 7 repo for Debian 8
- MariaDB now checks for OS version, so the correct repo is used.
- Updated Softether to version 4.19 Build 9578 beta
- Minor tweaks and fixes

### 1.5.10 (2015-08-18)
- Added Wordpress install

### 1.5.9 (2015-08-16)
- Added Ghost blog with nginx as reverse proxy
- Removed lighttpd

### 1.5.8 (2015-08-04)
- Updated squid3 configuration for Debian 8
- Updated OpenVPN Installer.
- Updated Softether
- Removed Lighttpd support for debian 7
- Added Transmission BitTorrent client
- Other Minor tweaks

### 1.5.7 (2015-06-22)
- Added [Plex Media Server](https://github.com/eunas/essentials/wiki/plexmediaserver)
- Updated Softether VPN to latest build
- Changed file-allocation for aria2 to none.
- Minor tweaks and fixes

### 1.5.6 (2015-05-07)
- Updated nginx for Debian 8
- Minor tweaks and fixes

### 1.5.5 (2015-04-27)
 - Updated PHP and x2go server for Debian 8

### 1.5.4 (2015-04-01)

- Added TUN/TAP check
- Fixed error in SoftEtherVPN Bridge setup
- Fixed error In LEMP / LLMP stack setup.
- Disabled Squid3 logging
- Minor tweaks and fixes
- Applied NYR's latest commit to OpenVPN install.

### 1.5.3 (2015-02-27)

- Added Observium server and client install.
- phpMyAdmin is now cloned from the official github. Upping it to a newer version. [(Advanced features disabled.)](https://github.com/eunas/essentials/wiki/phpMyAdmin)
- Minor tweaks and fixes.

### 1.5.2 (2015-02-19)

- Re-engineered ssmtp install.
- Removed additional OS checks in openVPN install. (We already verified that.)
- Replaced php5-mysql with php5-mysqlnd for better performance.
- Added lighttpd 1.4.35 to webserver install.
- Updated NYR's OpenVPN script
- Fixed duplicate in php.ini
- Other minor stuff.

### 1.5.1 (2015-02-16)

- SSH port is now optional in "Secure system"
- New option for SoftEther VPN Server. Choose between "SecureNAT" or "Local Bridge" If Local Bridge is selected but TUN/TAP is not enabled, SecureNAT will be used instead.

### 1.5 (2015-02-14)

## Fixed:
- Error in MySQL Server installation.
- Dnsmasq unable to start on some OpenVZ systems.
- Various tweaks and fixes.
- Aria2 is no longer compiled on the server as low end systems would run out of memory in the process. It's now installed from the debian testing repository.

##New:
- Changed nginx repo from dotdeb to the official one.
- You can now choose between nginx version 1.6.x or 1.7.x
- nginx, PHP-FPM, MariaDB, Mysql, phpMyAdmin or any combination thereof, can now be installed in a single run.
- secure_mysql_installation is no longer optional.
- Supressed some output messages.
- Updated Nyr's OpenVPN installer.
- If apache2 is installed, remove it before installing nginx

### 1.4 (2015-02-07)

## Fixed:
- Certificate check in speedtest.net fixed
- Reworked the menu

## New:
- SoftEtherVPN
- Xfce desktop enviroment + X2Go server
- [Secure system](https://github.com/eunas/essentials/wiki/Secure-System)
 - Install fail2ban
 - Change SSH port
 - Prevent root SSH login
 - Create new user
- Wiki

## 1.3 (2015-02-04)

### Fixes:
- Fixed error in my.cnf

### New:
- Aria2 1.18.9 torrent client + Webui (Secret token security)
- Linux Dash PHP server monitor.
- Speedtest.net with image url to results.

## 1.2 (2015-01-03)

###Features:

  - New functions and clean up.
  - Seperated PHP-FPM and nginx
  - Tweaked nginx for lowend use.
  - Removed Apache2
  - Added FTPS to Pure-ftpd
  - Added port selection during pure-ftpd install
  - Added port selection during squid3 install
  - Minor changes to php.ini
  - Added php5-sqlite
  - Tweaked my.cnf for lowend use
  - Better OS info
  - Better info messages
  - Added Essentials script (See below)
  - Moved lftp to essentials

###Essentials:

Essentials will remove un-needed services and install some essentials.
Removes: apache2, bind9, samba, nscd, sendmail, portmap
Disables: xinetd, saslauthd
Installs: nano, rcconf, lftp, unzip
Added Disk I/O test and Network speed test.

###Todo
* Add easy vhost creation to nginx
* lighttpd and php installation
* More & better user management

