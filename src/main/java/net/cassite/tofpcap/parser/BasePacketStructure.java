package net.cassite.tofpcap.parser;

import io.vproxy.base.util.ByteArray;
import io.vproxy.base.util.Logger;

public class BasePacketStructure {
    private int totalLen;
    private int type;
    private int offsetAfterType;

    public int getTotalLen() {
        return totalLen;
    }

    public int getType() {
        return type;
    }

    public int getOffsetAfterType() {
        return offsetAfterType;
    }

    public void from(ByteArray data) {
        assert Logger.lowLevelDebug("BasePacketStructure.from: data=" + data.toHexString());
        int off = 0;

        totalLen = data.int32ReverseNetworkByteOrder(off);
        off += 4;

        int _off = data.int32ReverseNetworkByteOrder(off);
        off += 4;
        off += _off;
        off += 4;

        off += 4;
        _off = data.int32ReverseNetworkByteOrder(off);
        off += 4;
        off += _off;
        off += 4;

        type = data.int32ReverseNetworkByteOrder(off);
        off += 4;

        offsetAfterType = off;
    }
}
