package net.cassite.tofpcap.util;

import io.vproxy.base.util.ByteArray;
import io.vproxy.base.util.coll.Tuple;

public class Utils {
    private Utils() {
    }

    public static Tuple<ByteArray, Integer> readLen4Data(ByteArray arr, int off) {
        int len = arr.int32ReverseNetworkByteOrder(off);
        var data = arr.sub(off + 4, len);
        int retLen = 4 + len + (len % 4 == 0 ? 0 : 4 - len % 4);
        return new Tuple<>(data, retLen);
    }

    // 0x20, 0x00, 0x00, 0x00, .., .., .., .. ...
    public static int findLen4Hex32(ByteArray data, int off) {
        int state = 0;
        for (int i = off; i < data.length(); ++i) {
            byte b = data.get(i);
            if (state == 0) {
                if (b == 0x20) {
                    state = 1;
                } // else { /* do nothing */ }
            } else if (1 <= state && state <= 3) {
                if (b == 0x00) {
                    ++state;
                } else {
                    i -= state;
                    state = 0;
                }
            } else if (state == 36) {
                return i;
            } else {
                if (('A' <= b && b <= 'Z') || ('0' <= b && b <= '9')) {
                    ++state;
                } else {
                    i -= state;
                    state = 0;
                }
            }
        }
        return -1;
    }

    public static int findLastLen4Data(ByteArray data, int off) {
        int minDataLen = 0;
        int maxDataLen = 0;
        while (true) {
            if (off < 4) {
                return -1;
            }
            int len = data.int32ReverseNetworkByteOrder(off - 4);
            if (minDataLen <= len && len <= maxDataLen) {
                return off - 4;
            }
            if (minDataLen == 0) {
                minDataLen = 1;
                maxDataLen = 4;
            } else {
                minDataLen += 4;
                maxDataLen += 4;
            }
            off -= 4;
        }
    }
}
