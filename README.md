```mqtt-arp``` is an imaginatively named program that uses the Linux kernel netlink interface to watch for details of hosts making ARP requests. It uses these requests to determine if a device is present and report that information via MQTT. I use it on my [OpenWRT](https://openwrt.org/) router to report to a [Home Assistant](https://www.home-assistant.io/) instance.

Rather than reporting all MAC addresses seen ```mqtt-arp``` takes a list of MACs to watch for. I have this configured for my phone, resulting in a reasonable proxy for whether I am home or not. ```mqtt-arp``` will report as soon as the device is seen, and send rate-limited (at most once every 2 minutes) updates when it is seen again. If the device is not seen for at least 10 minutes the location will be reported as "unknown".

There is basic configuration file support; by default ```mqtt-arp``` will read ```/etc/mqtt-arp.conf```. The location can be overridden, see below. 
The following aspects can be configured at run time:

 * MQTT host (-h / --host / mqtt_host)
 * MQTT post (-p / --port / mqtt_port)
 * MQTT username (-u / --username / mqtt_user)
 * MQTT password (-P / --password / mqtt_pass)
 * MQTT topic (-t / --topic / mqtt_topic)
 * Location to report when device is present (-l / --location / location)
 * Path to SSL certificate bundle (-c / --capath / capath)
 * MAC addresses to watch for  (-m / --mac / mac)
 * Read config file at specific location (-f / --configfile / file path)

This code is released as GPLv3+ and is available at [https://the.earth.li/gitweb/?p=mqtt-arp.git;a=summary](https://the.earth.li/gitweb/?p=mqtt-arp.git;a=summary) or on GitHub for easy whatever at [https://github.com/u1f35c/mqtt-arp](https://github.com/u1f35c/mqtt-arp)
