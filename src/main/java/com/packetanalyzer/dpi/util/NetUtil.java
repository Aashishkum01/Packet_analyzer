package com.packetanalyzer.dpi.util;

import com.packetanalyzer.dpi.model.AppType;

import java.util.Locale;

public final class NetUtil {
    public static final int ETHER_TYPE_IPV4 = 0x0800;
    public static final int ETHER_TYPE_IPV6 = 0x86DD;
    public static final int ETHER_TYPE_ARP = 0x0806;

    public static final int PROTOCOL_ICMP = 1;
    public static final int PROTOCOL_TCP = 6;
    public static final int PROTOCOL_UDP = 17;

    private NetUtil() {
    }

    public static int parseIpv4ToInt(String ip) {
        String[] octets = ip.split("\\.");
        if (octets.length != 4) {
            throw new IllegalArgumentException("Invalid IPv4 address: " + ip);
        }
        int result = 0;
        for (int i = 0; i < octets.length; i++) {
            int octet = Integer.parseInt(octets[i]);
            result |= (octet & 0xFF) << (i * 8);
        }
        return result;
    }

    public static String ipv4ToString(byte[] data, int offset) {
        return (data[offset] & 0xFF) + "."
            + (data[offset + 1] & 0xFF) + "."
            + (data[offset + 2] & 0xFF) + "."
            + (data[offset + 3] & 0xFF);
    }

    public static String ipv4ToString(int ip) {
        return (ip & 0xFF) + "."
            + ((ip >>> 8) & 0xFF) + "."
            + ((ip >>> 16) & 0xFF) + "."
            + ((ip >>> 24) & 0xFF);
    }

    public static String protocolToString(int protocol) {
        return switch (protocol) {
            case PROTOCOL_ICMP -> "ICMP";
            case PROTOCOL_TCP -> "TCP";
            case PROTOCOL_UDP -> "UDP";
            default -> "Unknown(" + protocol + ")";
        };
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder builder = new StringBuilder();
        appendFlag(builder, flags, 0x02, "SYN");
        appendFlag(builder, flags, 0x10, "ACK");
        appendFlag(builder, flags, 0x01, "FIN");
        appendFlag(builder, flags, 0x04, "RST");
        appendFlag(builder, flags, 0x08, "PSH");
        appendFlag(builder, flags, 0x20, "URG");
        return builder.isEmpty() ? "none" : builder.toString().trim();
    }

    private static void appendFlag(StringBuilder builder, int flags, int mask, String label) {
        if ((flags & mask) != 0) {
            builder.append(label).append(' ');
        }
    }

    public static AppType classifyFromSni(String sni) {
        if (sni == null || sni.isBlank()) {
            return AppType.UNKNOWN;
        }

        String lower = sni.toLowerCase(Locale.ROOT);

        if (containsAny(lower, "google", "gstatic", "googleapis", "ggpht", "gvt1")) {
            return AppType.GOOGLE;
        }
        if (containsAny(lower, "youtube", "ytimg", "youtu.be", "yt3.ggpht")) {
            return AppType.YOUTUBE;
        }
        if (containsAny(lower, "facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")) {
            return AppType.FACEBOOK;
        }
        if (containsAny(lower, "instagram", "cdninstagram")) {
            return AppType.INSTAGRAM;
        }
        if (containsAny(lower, "whatsapp", "wa.me")) {
            return AppType.WHATSAPP;
        }
        if (containsAny(lower, "twitter", "twimg", "x.com", "t.co")) {
            return AppType.TWITTER;
        }
        if (containsAny(lower, "netflix", "nflxvideo", "nflximg")) {
            return AppType.NETFLIX;
        }
        if (containsAny(lower, "amazon", "amazonaws", "cloudfront", "aws")) {
            return AppType.AMAZON;
        }
        if (containsAny(lower, "microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing")) {
            return AppType.MICROSOFT;
        }
        if (containsAny(lower, "apple", "icloud", "mzstatic", "itunes")) {
            return AppType.APPLE;
        }
        if (containsAny(lower, "telegram", "t.me")) {
            return AppType.TELEGRAM;
        }
        if (containsAny(lower, "tiktok", "tiktokcdn", "musical.ly", "bytedance")) {
            return AppType.TIKTOK;
        }
        if (containsAny(lower, "spotify", "scdn.co")) {
            return AppType.SPOTIFY;
        }
        if (lower.contains("zoom")) {
            return AppType.ZOOM;
        }
        if (containsAny(lower, "discord", "discordapp")) {
            return AppType.DISCORD;
        }
        if (containsAny(lower, "github", "githubusercontent")) {
            return AppType.GITHUB;
        }
        if (containsAny(lower, "cloudflare", "cf-")) {
            return AppType.CLOUDFLARE;
        }
        return AppType.HTTPS;
    }

    private static boolean containsAny(String value, String... candidates) {
        for (String candidate : candidates) {
            if (value.contains(candidate)) {
                return true;
            }
        }
        return false;
    }
}
