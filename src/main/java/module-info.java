module net.cassite.tofpcap {
    requires io.vproxy.base;
    requires org.pcap4j.core;
    requires org.pcap4j.packetfactory.statik;
    requires slf4j.api;

    exports net.cassite.tofpcap;
    exports net.cassite.tofpcap.messages;
    exports net.cassite.tofpcap.parser;
    exports net.cassite.tofpcap.util;
}
