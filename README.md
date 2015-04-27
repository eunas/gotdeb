##Essentials

Interactive essentials install script for VPS or Dedicated servers.
Build with low end systems in mind.
Requires Debian version 7.x or 8.x

###Installation
Run the script and follow the assistant:

`wget https://raw.githubusercontent.com/eunas/essentials/master/setup.sh --no-check-certificate`
`chmod +x setup.sh && ./setup.sh`

###Script content

* Webserver
 * nginx 1.6.x
 * nginx 1.7.x
 * lighttpd 1.4.35
* PHP-FPM 5.6
* MySQL Server
* MariaDB server
* [phpMyAdmin](https://github.com/eunas/essentials/wiki/phpMyAdmin)
* PureFTPD (FTPS enabled)
* Java 7 JDK
* MCMyAdmin x64
* pptp server
* OpenVPN Server (Works on NAT)
* [SoftEtherVPS (Works on NAT)](https://github.com/eunas/essentials/wiki/SoftEtherVPN)
* Squid3 Proxy Server
* sSMTP server
* Aria2 + webui
* [X2Go + xfce Desktop](https://github.com/eunas/essentials/wiki/Remote-Desktop)
* [Observium](https://github.com/eunas/essentials/wiki/Observium)
 * Server
 * Client
* Linux Dash server monitor
* User Management
 * Add user
 * Delete user
 * List Users
* System Management
 * Remove unneeded packages and services
 * Install essentials packages
 * Update timezone
 * System tests
 * [Secure System](https://github.com/eunas/essentials/wiki/Secure-System)
 * Speedtest.net
 * Get OS Version
* About


###Disclaimer
Parts of the files are scripts found on various sites on the internet, and either modified or included.
Tested on a [LowEndSpirit](http://lowendspirit.com/) VPS with 128 MB Ram

###Credits
Xeoncross, mikel, Falko Timme, road warrior, Nyr and many others.
