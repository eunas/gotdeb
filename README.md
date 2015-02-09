##Essentials

Interactive essentials install script for VPS or Dedicated servers.
Build with low end systems in mind.
Requires Debian version 7.x

###Installation
Run the script and follow the assistant:

`wget https://raw.githubusercontent.com/eunas/essentials/master/setup.sh --no-check-certificate`
`chmod +x setup.sh && ./setup.sh`

###Script content

* nginx 1.6.2
* PHP-FPM 5.6.5
* MySQL Server
* MariaDB server
* phpMyAdmin
* PureFTPD (FTPS enabled)
* Java 7 JDK
* MCMyAdmin x64
* pptp server
* OpenVPN Server (Works on NAT)
* [SoftEtherVPS (Works on NAT)](https://github.com/eunas/essentials/wiki/SoftEtherVPN)
* Squid3 Proxy Server
* sSMTP server
* Aria2 1.18.9 + webui
* [X2Go + xfce Desktop](https://github.com/eunas/essentials/wiki/Remote-Desktop)
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
Xeoncross, mikel, Falko Timme, road warrior and many others.
