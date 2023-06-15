# TofPcapJava

## How to run

### prerequisites

* You must know the ip address of your tof server.
* Have JDK 17 installed (You can use the latest jdk here: [https://adoptium.net](https://adoptium.net))
* Install WinPcap

> Please note that the `choco` way of installing WinPcap is out-dated.  
> You can go to the official website to download and install: [https://www.winpcap.org](https://www.winpcap.org)

### Run

Run `./gradlew run --args='help'` to see the man page as well as your available network interfaces.

Run `./gradle run --args='dev={dev name or ip} host={ip of the tof server}'` to start capturing and parsing tof packets.

## Capabilities

Currently, it supports:

* chat messages
