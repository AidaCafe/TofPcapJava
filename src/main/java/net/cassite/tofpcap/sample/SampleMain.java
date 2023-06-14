package net.cassite.tofpcap.sample;

import io.vproxy.base.util.Logger;
import io.vproxy.vfd.IP;
import net.cassite.tofpcap.MessageType;
import net.cassite.tofpcap.TofPcap;
import net.cassite.tofpcap.messages.ChatMessage;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.net.InetAddress;
import java.util.Collections;

public class SampleMain {
    private static final String HELP_STR =
        """
            Usage: dev={dev name or ip} host={ip of the tof server}
            """.trim();

    private static String getHelpStr() {
        var netifs = Collections.<PcapNetworkInterface>emptyList();
        try {
            netifs = Pcaps.findAllDevs();
        } catch (PcapNativeException ignore) {
        }
        var sb = new StringBuilder(HELP_STR);
        if (!netifs.isEmpty()) {
            sb.append("\n")
                .append("available network interfaces:\n");
            for (var n : netifs) {
                sb.append("\t").append(n.getName());
                if (n.getDescription() != null) {
                    sb.append("\t").append(n.getDescription());
                }
                sb.append("\n");
                var addrs = n.getAddresses();
                for (var a : addrs) {
                    sb.append("\t\t").append(IP.from(a.getAddress()).formatToIPString()).append("\n");
                }
            }
        }
        return sb.toString().trim();
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println(getHelpStr());
            return;
        }
        String dev = null;
        String host = null;
        for (var arg : args) {
            if (arg.equals("-h") || arg.equals("--help") || arg.equals("-help") || arg.equals("help")) {
                System.out.println(getHelpStr());
                return;
            } else if (arg.startsWith("dev=")) {
                dev = arg.substring("dev=".length()).trim();
            } else if (arg.startsWith("host=")) {
                host = arg.substring("host=".length()).trim();
            } else {
                System.out.println("unknown arg: " + arg);
                return;
            }
        }
        if (dev == null || dev.isEmpty()) {
            System.out.println("missing dev");
            return;
        }
        if (host == null || host.isEmpty()) {
            System.out.println("missing host");
            return;
        }

        IP ip;
        try {
            ip = IP.from(host);
        } catch (Throwable t) {
            System.out.println("invalid ip address: " + host);
            return;
        }

        PcapNetworkInterface netif;
        try {
            netif = Pcaps.getDevByName(dev);
            if (netif == null) {
                throw new RuntimeException("getDevByName(" + dev + ") returns null");
            }
        } catch (Throwable t) {
            try {
                var inetaddr = InetAddress.getByAddress(IP.from(dev).getAddress());
                netif = Pcaps.getDevByAddress(inetaddr);
                if (netif == null) {
                    throw new RuntimeException("getDevByAddress(" + inetaddr + ") returns null");
                }
            } catch (Throwable t2) {
                System.out.println("unable to retrieve dev " + dev);
                t.printStackTrace(System.out);
                t2.printStackTrace(System.out);
                return;
            }
        }

        var tofPcap = new TofPcap(netif, ip);
        tofPcap.addListener(MessageType.CHAT, evt -> {
            var chat = (ChatMessage) evt.msg();
            Logger.alert(chat.toString());
        });

        try {
            tofPcap.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
