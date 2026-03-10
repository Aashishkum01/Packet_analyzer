package com.packetanalyzer.dpi.cli;

import java.util.Arrays;

public final class DpiApplication {
    private DpiApplication() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0 || "--help".equals(args[0]) || "-h".equals(args[0])) {
            printUsage();
            return;
        }

        String mode = args[0].toLowerCase();
        String[] forwardedArgs = Arrays.copyOfRange(args, 1, args.length);

        switch (mode) {
            case "analyze" -> PacketAnalyzerCli.main(forwardedArgs);
            case "simple" -> SimpleDpiCli.main(forwardedArgs);
            case "mt" -> MultithreadedDpiCli.main(forwardedArgs);
            default -> {
                System.err.println("Unknown mode: " + args[0]);
                printUsage();
                System.exit(1);
            }
        }
    }

    private static void printUsage() {
        System.out.println("Packet Analyzer - Java DPI Project");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  java -jar target/packet-analyzer-1.0-SNAPSHOT.jar analyze <pcap_file> [max_packets]");
        System.out.println("  java -jar target/packet-analyzer-1.0-SNAPSHOT.jar simple <input.pcap> <output.pcap> [options]");
        System.out.println("  java -jar target/packet-analyzer-1.0-SNAPSHOT.jar mt <input.pcap> <output.pcap> [options]");
        System.out.println();
        System.out.println("Modes:");
        System.out.println("  analyze   Inspect packets and print decoded packet details");
        System.out.println("  simple    Run the single-threaded DPI pipeline");
        System.out.println("  mt        Run the multi-threaded DPI pipeline");
    }
}
