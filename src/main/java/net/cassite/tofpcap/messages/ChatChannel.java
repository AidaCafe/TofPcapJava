package net.cassite.tofpcap.messages;

public enum ChatChannel {
    WORLD(1),
    TEAM(3),
    GUILD(8),
    COOP(9),
    ;

    public final int num;

    ChatChannel(int num) {
        this.num = num;
    }

    public static ChatChannel valueOfOrNull(int channel) {
        if (channel == WORLD.num) return WORLD;
        if (channel == TEAM.num) return TEAM;
        if (channel == GUILD.num) return GUILD;
        if (channel == COOP.num) return COOP;
        return null;
    }

    public static ChatChannel valueOf0(String s) {
        return switch (s) {
            case "WORLD", "world" -> WORLD;
            case "TEAM", "team" -> TEAM;
            case "GUILD", "guild" -> GUILD;
            case "COOP", "coop" -> COOP;
            default -> throw new IllegalArgumentException("unknown string for ChatChannel: " + s);
        };
    }
}
