nuts-auth [![Build Status](https://travis-ci.org/thusoy/nuts-auth.svg?branch=master)](https://travis-ci.org/thusoy/nuts-auth)
================

Experiments for my project on authenticating a radio uplink to the NUTS cubesat. The final report can be found [here](report/nuts-uplink-authentication.pdf).

[Code coverage](http://thusoy.github.io/nuts-auth)

RPi setup
=========

Assumes you have a Raspbian image installed on a RPi with a WiFi dongle.
This setup uses the model B+ RPi with a WiPi dongle.

Install `hostapd` and configure the RPi as a access point:

    $ sudo apt-get install hostapd

Configuration:

    $ sudo sh -c 'echo DAEMON_CONF="/etc/hostapd/hostapd.conf" >> /etc/default/hostapd"'

Copy the `hostapd.conf` from the repo to `/etc/hostapd/hostapd.conf`, and
restart the service:

    $ sudo service hostapd restart

Install `dnsmasq` to assign IP addresses to peers on the network:

    $ sudo apt-get install dnsmasq
    $ sudo sh -c "echo -e 'interface=wlan0\ndhcp-range=10.0.0.2,10.0.0.255,255.255.255.0,12h\nlisten-address=10.0.0.1' >> /etc/dnsmasq.conf"
    $ sudo service dnsmasq restart

Configure the `/etc/network/interfaces` for the server:

    auto lo

    iface lo inet loopback
    iface eth0 inet dhcp

    allow-hotplug wlan0

    auto wlan0
    iface wlan0 inet static
        address 10.0.0.1
        netmask 255.255.255.0
    iface default inet dhcp

And similarliy for the client:

    auto lo

    iface lo inet loopback
    iface eth0 inet dhcp

    allow-hotplug wlan0

    auto wlan0
    iface wlan0 inet dhcp
            wireless-essid NUTS
    iface default inet dhcp


On each of the devices, install the necessary libraries to run the NUTS scheme:

    $ sudo apt-get update
    $ sudo apt-get install build-essential python-dev python-pip -y
    $ sudo pip install pysha3
    $ sudo pip install -e .

Transport for the example app (see `sat.py` and `gs.py`) uses UDP.


Troubleshooting
===============

Connection lost between client and server? It might have been the `hostapd` driver crashing, if you run `ifconfig wlan0` on the server and it doesn't report an IP, that's likely the problem. Try to restart the service to bring it back, `sudo service hostapd restart`, and bring up the connection again on the client, `sudo ifup wlan0`.
