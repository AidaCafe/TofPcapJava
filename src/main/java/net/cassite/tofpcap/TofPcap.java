package net.cassite.tofpcap;

import io.vproxy.base.util.ByteArray;
import io.vproxy.base.util.LogType;
import io.vproxy.base.util.Logger;
import io.vproxy.base.util.coll.Tuple;
import io.vproxy.vfd.IP;
import io.vproxy.vpacket.AbstractIpPacket;
import io.vproxy.vpacket.EthernetPacket;
import io.vproxy.vpacket.PacketDataBuffer;
import io.vproxy.vpacket.TcpPacket;
import net.cassite.tofpcap.messages.ChatMessage;
import net.cassite.tofpcap.util.Utils;
import net.cassite.tofpcap.util.TofConsts;
import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeoutException;

public class TofPcap {
    private final PcapNetworkInterface netif;
    private final IP capHost;
    private final Map<MessageType, List<MessageListener>> listeners = new ConcurrentHashMap<>();
    private volatile boolean started = false;
    private volatile boolean running = false;
    private PcapHandle pcapHandle = null;
    private RetransmissionSuppressor retransmissionSuppressor;

    public TofPcap(PcapNetworkInterface netif, IP capHost) {
        this.netif = netif;
        this.capHost = capHost;
    }

    public boolean isStarted() {
        return started;
    }

    public void start() throws Exception {
        synchronized (this) {
            if (started) {
                throw new IllegalStateException("is already running");
            }
            started = true;
        }
        try {
            prepare();
            run();
        } finally {
            try {
                destroy();
            } catch (Throwable t) {
                Logger.error(LogType.ALERT, "failed to finalize TofPcap", t);
            }
            started = false;
        }
    }

    private void prepare() throws Exception {
        int snapLen = 65536;
        PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
        int timeout = 500;
        pcapHandle = netif.openLive(snapLen, mode, timeout);
        var filter = "tcp and src host " + capHost.formatToIPString(); // TODO might support udp and egress traffic in the future
        pcapHandle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);

        retransmissionSuppressor = new RetransmissionSuppressor();
    }

    private void destroy() {
        var handle = pcapHandle;
        pcapHandle = null;
        if (handle != null) {
            handle.close();
        }
        retransmissionSuppressor = null;
    }

    private void run() {
        running = true;
        while (running) {
            Packet packet;
            try {
                packet = pcapHandle.getNextPacketEx();
            } catch (TimeoutException ignore) {
                continue;
            } catch (Throwable t) {
                Logger.error(LogType.ALERT, "failed to retrieve next packet", t);
                continue;
            }
            try {
                handlePacket(packet.getRawData());
            } catch (Throwable t) {
                Logger.error(LogType.ALERT, "failed to handle packet", t);
            }
        }
    }

    private void handlePacket(byte[] rawData) throws Exception {
        var raw = ByteArray.from(rawData);
        var eth = new EthernetPacket();
        var err = eth.from(new PacketDataBuffer(raw));
        if (err != null) {
            throw new Exception(err);
        }
        assert Logger.lowLevelNetDebug("received packet: " + eth);
        var nwPkt = eth.getPacket();
        if (!(nwPkt instanceof AbstractIpPacket)) {
            return;
        }
        var ipPkt = (AbstractIpPacket) nwPkt;
        boolean isIngress;
        if (ipPkt.getSrc().equals(capHost)) {
            isIngress = true;
        } else if (ipPkt.getDst().equals(capHost)) {
            isIngress = false;
        } else { // not expected packet
            return;
        }
        var tpPkt = ((AbstractIpPacket) nwPkt).getPacket();
        if (tpPkt instanceof TcpPacket tcpPkt) {
            if (tcpPkt.getData().length() == 0) {
                return;
            }
            if (retransmissionSuppressor.check(ipPkt, tcpPkt, isIngress)) {
                handleTcp(tcpPkt.getData(), isIngress);
            }
        }
        // TODO might support udp packets in the future
    }

    private void handleTcp(ByteArray data, boolean isIngress) {
        if (!isIngress)
            return; // TODO might support egress in the future
        int _len = data.int32ReverseNetworkByteOrder(0);
        if (_len != data.length() - 4) {
            assert Logger.lowLevelDebug("unexpected packet, _len(" + _len + ") != data.length(" + data.length() + ") - 4");
            return;
        }

        var parseTup = parsePacketType(data, 0);

        if (parseTup._1 == TofConsts.PACKET_TYPE_CHAT) {
            handleChat(data, parseTup._2);
        } else {
            assert Logger.lowLevelDebug("unknown packet type " + parseTup._1);
        }
    }

    // return <type, new-off>
    public static Tuple<Integer, Integer> parsePacketType(ByteArray data, int off) {
        assert Logger.lowLevelDebug("parsePacketType off=" + off + ", data=" + data.toHexString());
        int _len = data.int32ReverseNetworkByteOrder(off);
        off += 4;

        if (_len != data.length() - 4) {
            throw new RuntimeException("invalid packet");
        }

        int _off = data.int32ReverseNetworkByteOrder(off);
        off += 4;
        off += _off;
        off += 4;

        off += 4;
        _off = data.int32ReverseNetworkByteOrder(off);
        off += 4;
        off += _off;
        off += 4;

        int flag = data.int32ReverseNetworkByteOrder(off);
        off += 4;

        return new Tuple<>(flag, off);
    }

    public static Tuple<ChatMessage, Integer> parseChatMessage(ByteArray data, int off) {
        assert Logger.lowLevelDebug("parseChatMessage off=" + off + ", data=" + data.toHexString());
        int endOff = Utils.findLen4Hex32(data, off);
        if (endOff == -1) {
            throw new IllegalArgumentException("invalid packet, cannot find first Len4Hex32");
        }
        off = endOff - 36;
        off = Utils.findLastLen4Data(data, off);
        if (off == -1) {
            throw new IllegalArgumentException("invalid packet, cannot find message");
        }
        var tup = Utils.readLen4Data(data, off);
        var message = tup._1.toString();
        while (message.isEmpty()) {
            off = Utils.findLastLen4Data(data, off);
            if (off == -1) {
                break;
            }
            tup = Utils.readLen4Data(data, off);
            message = tup._1.toString();
        }

        off = Utils.findLastLen4Data(data, off);
        if (off != -1 && message.isEmpty()) {
            tup = Utils.readLen4Data(data, off);
            message = tup._1.toString();
        }

        int nextOff = Utils.findLen4Hex32(data, endOff);
        if (nextOff == -1) {
            throw new IllegalArgumentException("invalid packet, cannot find second Len4Hex32");
        }
        off = nextOff + 4;

        var strings = new ArrayList<String>();

        while (off < data.length() - 1) {
            tup = Utils.readLen4Data(data, off);
            var str = tup._1.toString();
            off += tup._2;

            if (str.isBlank()) {
                continue;
            }
            strings.add(str);
        }

        var avatarFrame = strings.get(0);
        var avatar = strings.get(1);
        var chatBubble = strings.get(strings.size() - 3);
        var title = strings.get(strings.size() - 2);
        var nickname = strings.get(strings.size() - 1);

        var msg = new ChatMessage(
            message,
            avatarFrame, avatar,
            chatBubble, title, nickname);
        return new Tuple<>(msg, off);
    }

    private void handleChat(ByteArray data, int off) {
        var parseTup = parseChatMessage(data, off);
        alertMessage(MessageType.CHAT, parseTup._1);
    }

    public void stop() {
        running = false;
        while (started) {
            try {
                //noinspection BusyWait
                Thread.sleep(1);
            } catch (InterruptedException ignore) {
            }
        }
    }

    private void alertMessage(MessageType type, ChatMessage msg) {
        var ls = listeners.get(type);
        if (ls == null) {
            return;
        }
        for (var lsn : ls) {
            lsn.onMessage(new MessageEvent(type, msg));
        }
    }

    public synchronized void addListener(MessageType type, MessageListener listener) {
        var ls = listeners.get(type);
        if (ls == null) {
            ls = new CopyOnWriteArrayList<>();
            listeners.put(type, ls);
        }
        ls.add(listener);
    }

    public synchronized void removeListener(MessageListener listener) {
        var keys = new HashSet<>(listeners.keySet());
        for (var k : keys) {
            var ls = listeners.get(k);
            if (ls.contains(listener)) {
                if (ls.size() == 1) {
                    listeners.remove(k);
                } else {
                    ls.remove(listener);
                }
            }
        }
    }
}
