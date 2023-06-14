package net.cassite.tofpcap.messages;

import net.cassite.tofpcap.Message;

public class ChatMessage implements Message {
    public final String message;
    public final String avatarFrame;
    public final String avatar;
    public final String chatBubble;
    public final String title;
    public final String nickName;

    public ChatMessage(String message, String avatarFrame, String avatar, String chatBubble, String title, String nickName) {
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
               "\n\tmessage='" + message + '\'' +
               "\n\tavatarFrame='" + avatarFrame + '\'' +
               "\n\tavatar='" + avatar + '\'' +
               "\n\tchatBubble='" + chatBubble + '\'' +
               "\n\ttitle='" + title + '\'' +
               "\n\tnickName='" + nickName + '\'' +
               "\n}";
    }
}
