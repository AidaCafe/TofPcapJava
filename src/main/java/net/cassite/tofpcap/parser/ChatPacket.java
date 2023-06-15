package net.cassite.tofpcap.parser;

import io.vproxy.base.util.ByteArray;
import io.vproxy.base.util.Logger;
import net.cassite.tofpcap.messages.ChatMessage;
import net.cassite.tofpcap.util.Utils;

import java.util.ArrayList;

public class ChatPacket {
    private int firstLen4Hex32EndingOffset;
    private int secondLen4Hex32EndingOffset;

    private String message;
    private String avatarFrame;
    private String avatar;
    private String chatBubble;
    private String title;
    private String nickName;

    public int getFirstLen4Hex32EndingOffset() {
        return firstLen4Hex32EndingOffset;
    }

    public int getSecondLen4Hex32EndingOffset() {
        return secondLen4Hex32EndingOffset;
    }

    public String getMessage() {
        return message;
    }

    public String getAvatarFrame() {
        return avatarFrame;
    }

    public String getAvatar() {
        return avatar;
    }

    public String getChatBubble() {
        return chatBubble;
    }

    public String getTitle() {
        return title;
    }

    public String getNickName() {
        return nickName;
    }

    public void from(ByteArray data) {
        assert Logger.lowLevelDebug("ChatPacket.from: data=" + data.toHexString());
        int off = 0;

        firstLen4Hex32EndingOffset = Utils.findLen4Hex32(data, off);
        if (firstLen4Hex32EndingOffset == -1) {
            throw new IllegalArgumentException("invalid packet, cannot find first Len4Hex32");
        }
        off = firstLen4Hex32EndingOffset - 36;
        off = Utils.findLastLen4Data(data, off);
        if (off == -1) {
            throw new IllegalArgumentException("invalid packet, cannot find message");
        }
        var tup = Utils.readLen4Data(data, off);
        message = tup._1.toString();
        while (message.isEmpty()) {
            off = Utils.findLastLen4Data(data, off);
            if (off == -1) {
                break;
            }
            tup = Utils.readLen4Data(data, off);
            message = tup._1.toString();
        }

        secondLen4Hex32EndingOffset = Utils.findLen4Hex32(data, firstLen4Hex32EndingOffset);
        if (secondLen4Hex32EndingOffset == -1) {
            throw new IllegalArgumentException("invalid packet, cannot find second Len4Hex32");
        }
        off = secondLen4Hex32EndingOffset + 4;

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

        avatarFrame = strings.get(0);
        avatar = strings.get(1);
        chatBubble = strings.get(strings.size() - 3);
        title = strings.get(strings.size() - 2);
        nickName = strings.get(strings.size() - 1);
    }

    public ChatMessage buildMessage() {
        return new ChatMessage(
            getMessage(),
            getAvatarFrame(), getAvatar(),
            getChatBubble(), getTitle(), getNickName());
    }
}
