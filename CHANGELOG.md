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

