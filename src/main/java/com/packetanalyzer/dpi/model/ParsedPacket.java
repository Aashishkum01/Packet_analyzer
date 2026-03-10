package com.packetanalyzer.dpi.model;

public final class ParsedPacket {
    private int timestampSec;
    private int timestampUsec;
    private String srcMac;
    private String destMac;
    private int etherType;
    private boolean hasIp;
    private int ipVersion;
    private String srcIp;
    private String destIp;
    private int protocol;
    private int ttl;
    private boolean hasTcp;
    private boolean hasUdp;
    private int srcPort;
    private int destPort;
    private int tcpFlags;
    private long seqNumber;
    private long ackNumber;
    private int payloadOffset;
    private int payloadLength;

    public int timestampSec() { return timestampSec; }
    public void setTimestampSec(int value) { this.timestampSec = value; }
    public int timestampUsec() { return timestampUsec; }
    public void setTimestampUsec(int value) { this.timestampUsec = value; }
    public String srcMac() { return srcMac; }
    public void setSrcMac(String value) { this.srcMac = value; }
    public String destMac() { return destMac; }
    public void setDestMac(String value) { this.destMac = value; }
    public int etherType() { return etherType; }
    public void setEtherType(int value) { this.etherType = value; }
    public boolean hasIp() { return hasIp; }
    public void setHasIp(boolean value) { this.hasIp = value; }
    public int ipVersion() { return ipVersion; }
    public void setIpVersion(int value) { this.ipVersion = value; }
    public String srcIp() { return srcIp; }
    public void setSrcIp(String value) { this.srcIp = value; }
    public String destIp() { return destIp; }
    public void setDestIp(String value) { this.destIp = value; }
    public int protocol() { return protocol; }
    public void setProtocol(int value) { this.protocol = value; }
    public int ttl() { return ttl; }
    public void setTtl(int value) { this.ttl = value; }
    public boolean hasTcp() { return hasTcp; }
    public void setHasTcp(boolean value) { this.hasTcp = value; }
    public boolean hasUdp() { return hasUdp; }
    public void setHasUdp(boolean value) { this.hasUdp = value; }
    public int srcPort() { return srcPort; }
    public void setSrcPort(int value) { this.srcPort = value; }
    public int destPort() { return destPort; }
    public void setDestPort(int value) { this.destPort = value; }
    public int tcpFlags() { return tcpFlags; }
    public void setTcpFlags(int value) { this.tcpFlags = value; }
    public long seqNumber() { return seqNumber; }
    public void setSeqNumber(long value) { this.seqNumber = value; }
    public long ackNumber() { return ackNumber; }
    public void setAckNumber(long value) { this.ackNumber = value; }
    public int payloadOffset() { return payloadOffset; }
    public void setPayloadOffset(int value) { this.payloadOffset = value; }
    public int payloadLength() { return payloadLength; }
    public void setPayloadLength(int value) { this.payloadLength = value; }
}
