package net.cassite.tofpcap.messages;

import net.cassite.tofpcap.Message;

public class ChatMessage implements Message {
    public final int channelNum;
    public final ChatChannel channel;
    public final String message;
    public final String avatarFrame;
    public final String avatar;
    public final String chatBubble;
    public final String title;
    public final String nickName;

    public ChatMessage(int channel, String message, String avatarFrame, String avatar, String chatBubble, String title, String nickName) {
        this.channelNum = channel;
        this.channel = ChatChannel.valueOfOrNull(channel);
        this.message = message;
        this.avatarFrame = avatarFrame;
        this.avatar = avatar;
        this.chatBubble = chatBubble;
        this.title = title;
        this.nickName = nickName;
    }

    @Override
    public String toString() {
        return "ChatMessage{" +
               "\n\tchannel=" + channelNum + "(" + channel + ")" +
               "\n\tmessage=" + (message == null ? "null" : ("'" + message + "'")) +
               "\n\tavatarFrame=" + (avatarFrame == null ? "null" : ("'" + avatarFrame + "'")) +
               "\n\tavatar=" + (avatar == null ? "null" : ("'" + avatar + "'")) +
               "\n\tchatBubble=" + (chatBubble == null ? "null" : ("'" + chatBubble + "'")) +
               "\n\ttitle=" + (title == null ? "null" : ("'" + title + "'")) +
               "\n\tnickName=" + (nickName == null ? "null" : ("'" + nickName + "'")) +
               "\n}";
    }
}
