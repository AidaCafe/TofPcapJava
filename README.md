# TofPcapJava

## How to run

### prerequisites

* You must know the ip address of your tof server.
* Have JDK 17 installed (You can use the latest jdk here: [https://adoptium.net](https://adoptium.net))
* Install WinPcap

> Please note that the `choco` way of installing WinPcap is out-dated.  
> You can go to the official website to download and install: [https://www.winpcap.org](https://www.winpcap.org)

### Run Sample

Run `./gradlew run --args='help'` to see the man page as well as your available network interfaces.

Run `./gradle run --args='dev={dev name or ip} host={ip of the tof server}'` to start capturing and parsing tof packets.

Add `-Dea=true` and `-Djavax.net.debug=all` to enable debugging logs.

## Use as a library

### dependency

**maven:**

```xml
<dependency>
  <groupId>net.cassite</groupId>
  <artifactId>tof-pcap-java</artifactId>
  <version>1.0.0</version>
</dependency>
```

**gradle:**

```groovy
implementation 'net.cassite:tof-pcap-java:1.0.0'
```

### usage

```java
var netif = Pcaps.getDevByXxx("...");
var ip = IP.from("tof server ip");

var cap = new TofPcap(netif, ip);
cap.addListener(MessageType.CHAT, evt -> {
  if (evt.type() != MessageType.CHAT) {
    return;
  }
  var chat = (ChatMessage) evt.msg();
  // ...
});

cap.start(); // will block
```

## Capabilities

Currently, it supports:

* chat messages
