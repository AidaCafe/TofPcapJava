package net.cassite.tofpcap;

import io.vproxy.base.util.Consts;
import io.vproxy.vfd.MacAddress;
import io.vproxy.vpacket.AbstractIpPacket;
import io.vproxy.vpacket.TcpPacket;
import io.vproxy.vpacket.tuples.PacketFullTuple;

import java.util.LinkedHashMap;
import java.util.Map;

public class RetransmissionSuppressor {
    private static final int CAPACITY = 4096;
    private static final int TIMEOUT = 60_000;
    private final Map<PacketFullTuple, ConnInfo> map = new LinkedHashMap<>() {
        @Override
        protected boolean removeEldestEntry(Map.Entry<PacketFullTuple, ConnInfo> eldest) {
            return size() > CAPACITY;
        }
    };

    private class ConnInfo {
        long seq;
        long lastTs;
    }

    // return true when check passes
    // return false if the packet is retransmission
    public boolean check(AbstractIpPacket ip, TcpPacket tcp, boolean isIngress) {
        PacketFullTuple tuple;
        if (isIngress) {
            tuple = new PacketFullTuple(0, MacAddress.ZERO, MacAddress.ZERO,
                ip.getSrc(), ip.getDst(), Consts.IP_PROTOCOL_TCP, tcp.getSrcPort(), tcp.getDstPort());
        } else {
            tuple = new PacketFullTuple(0, MacAddress.ZERO, MacAddress.ZERO,
                ip.getDst(), ip.getSrc(), Consts.IP_PROTOCOL_TCP, tcp.getDstPort(), tcp.getSrcPort());
        }
        var info = map.get(tuple);
        var now = System.currentTimeMillis();
        if (info != null && now - info.lastTs > TIMEOUT) {
            info = null;
        }
        if (info == null) {
            info = new ConnInfo();
            info.seq = tcp.getSeqNum();
            info.lastTs = now;
            map.put(tuple, info);
            return true;
        }
        if (info.seq > tcp.getSeqNum()) {
            return false;
        }
        info.seq = tcp.getSeqNum();
        info.lastTs = now;
        return true;
    }
}
