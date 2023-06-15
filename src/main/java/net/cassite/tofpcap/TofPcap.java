package net.cassite.tofpcap;

import io.vproxy.base.util.ByteArray;
import io.vproxy.base.util.LogType;
import io.vproxy.base.util.Logger;
import io.vproxy.vfd.IP;
import io.vproxy.vpacket.AbstractIpPacket;
import io.vproxy.vpacket.EthernetPacket;
import io.vproxy.vpacket.PacketDataBuffer;
import io.vproxy.vpacket.TcpPacket;
import net.cassite.tofpcap.messages.ChatMessage;
import net.cassite.tofpcap.parser.BasePacketStructure;
import net.cassite.tofpcap.parser.ChatPacket;
import net.cassite.tofpcap.util.TofConsts;
import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

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

        var basePacket = new BasePacketStructure();
        basePacket.from(data);

        if (basePacket.getType() == TofConsts.PACKET_TYPE_CHAT) {
            handleChat(data.sub(basePacket.getOffsetAfterType(), data.length() - basePacket.getOffsetAfterType()));
        } else {
            assert Logger.lowLevelDebug("unknown packet type " + basePacket.getType());
        }
    }

    private void handleChat(ByteArray data) {
        var chatPacket = new ChatPacket();
        chatPacket.from(data);
        alertMessage(MessageType.CHAT, chatPacket.buildMessage());
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
