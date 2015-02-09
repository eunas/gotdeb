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

