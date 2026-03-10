package com.packetanalyzer.dpi.inspect;

import java.nio.charset.StandardCharsets;

public final class SniExtractor {
    private SniExtractor() {
    }

    public static String extractTlsSni(byte[] payload, int offset, int length) {
        if (!isTlsClientHello(payload, offset, length)) {
            return null;
        }

        int cursor = offset + 5;
        int handshakeLength = readUint24(payload, cursor + 1);
        cursor += 4;
        if (cursor + handshakeLength > offset + length) {
            handshakeLength = offset + length - cursor;
        }

        cursor += 2 + 32;
        if (cursor >= offset + length) {
            return null;
        }

        int sessionIdLength = payload[cursor] & 0xFF;
        cursor += 1 + sessionIdLength;
        if (cursor + 2 > offset + length) {
            return null;
        }

        int cipherSuitesLength = readUint16(payload, cursor);
        cursor += 2 + cipherSuitesLength;
        if (cursor >= offset + length) {
            return null;
        }

        int compressionMethodsLength = payload[cursor] & 0xFF;
        cursor += 1 + compressionMethodsLength;
        if (cursor + 2 > offset + length) {
            return null;
        }

        int extensionsLength = readUint16(payload, cursor);
        cursor += 2;
        int extensionsEnd = Math.min(cursor + extensionsLength, offset + length);

        while (cursor + 4 <= extensionsEnd) {
            int extensionType = readUint16(payload, cursor);
            int extensionLength = readUint16(payload, cursor + 2);
            cursor += 4;

            if (cursor + extensionLength > extensionsEnd) {
                break;
            }

            if (extensionType == 0x0000) {
                if (extensionLength < 5) {
                    return null;
                }
                int sniListLength = readUint16(payload, cursor);
                if (sniListLength < 3) {
                    return null;
                }
                int sniType = payload[cursor + 2] & 0xFF;
                int sniLength = readUint16(payload, cursor + 3);
                if (sniType != 0x00 || sniLength > extensionLength - 5 || cursor + 5 + sniLength > extensionsEnd) {
                    return null;
                }
                return new String(payload, cursor + 5, sniLength, StandardCharsets.US_ASCII);
            }

            cursor += extensionLength;
        }

        return null;
    }

    public static boolean isTlsClientHello(byte[] payload, int offset, int length) {
        if (length < 9) {
            return false;
        }
        if ((payload[offset] & 0xFF) != 0x16) {
            return false;
        }
        int version = readUint16(payload, offset + 1);
        if (version < 0x0300 || version > 0x0304) {
            return false;
        }
        int recordLength = readUint16(payload, offset + 3);
        if (recordLength > length - 5) {
            return false;
        }
        return (payload[offset + 5] & 0xFF) == 0x01;
    }

    public static String extractHttpHost(byte[] payload, int offset, int length) {
        if (!isHttpRequest(payload, offset, length)) {
            return null;
        }

        int end = offset + length;
        for (int i = offset; i + 5 < end; i++) {
            if (matchesHostHeader(payload, i, end)) {
                int start = i + 5;
                while (start < end && (payload[start] == ' ' || payload[start] == '\t')) {
                    start++;
                }
                int valueEnd = start;
                while (valueEnd < end && payload[valueEnd] != '\r' && payload[valueEnd] != '\n') {
                    valueEnd++;
                }
                if (valueEnd > start) {
                    String host = new String(payload, start, valueEnd - start, StandardCharsets.US_ASCII);
                    int colon = host.indexOf(':');
                    return colon >= 0 ? host.substring(0, colon) : host;
                }
            }
        }
        return null;
    }

    public static String extractDnsQuery(byte[] payload, int offset, int length) {
        if (!isDnsQuery(payload, offset, length)) {
            return null;
        }
        int cursor = offset + 12;
        int end = offset + length;
        StringBuilder domain = new StringBuilder();

        while (cursor < end) {
            int labelLength = payload[cursor] & 0xFF;
            if (labelLength == 0) {
                break;
            }
            if (labelLength > 63 || cursor + 1 + labelLength > end) {
                return null;
            }
            cursor++;
            if (!domain.isEmpty()) {
                domain.append('.');
            }
            domain.append(new String(payload, cursor, labelLength, StandardCharsets.US_ASCII));
            cursor += labelLength;
        }

        return domain.isEmpty() ? null : domain.toString();
    }

    private static boolean isHttpRequest(byte[] payload, int offset, int length) {
        if (length < 4) {
            return false;
        }
        String[] methods = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};
        for (String method : methods) {
            if (matchesAscii(payload, offset, method)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isDnsQuery(byte[] payload, int offset, int length) {
        if (length < 12) {
            return false;
        }
        int flags = payload[offset + 2] & 0xFF;
        int qdCount = readUint16(payload, offset + 4);
        return (flags & 0x80) == 0 && qdCount > 0;
    }

    private static boolean matchesAscii(byte[] payload, int offset, String expected) {
        if (offset + expected.length() > payload.length) {
            return false;
        }
        for (int i = 0; i < expected.length(); i++) {
            if ((char) payload[offset + i] != expected.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    private static boolean matchesHostHeader(byte[] payload, int index, int end) {
        return index + 4 < end
            && (payload[index] == 'H' || payload[index] == 'h')
            && (payload[index + 1] == 'o' || payload[index + 1] == 'O')
            && (payload[index + 2] == 's' || payload[index + 2] == 'S')
            && (payload[index + 3] == 't' || payload[index + 3] == 'T')
            && payload[index + 4] == ':';
    }

    private static int readUint16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static int readUint24(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 16)
            | ((data[offset + 1] & 0xFF) << 8)
            | (data[offset + 2] & 0xFF);
    }
}
