# Demo Guide

This guide shows how to present the project clearly in an interview, portfolio review, or live demo.

## One-Line Pitch

This is a Java-based deep packet inspection project that reads PCAP network captures, parses packet headers, extracts domains from TLS SNI and HTTP Host headers, classifies traffic by application, and filters packets using configurable blocking rules.

## What The Project Is

This is not a Spring Boot app or a REST API.

It is a Java CLI networking project with three modes:

- `analyze`: inspect and print decoded packet details
- `simple`: run the single-threaded DPI engine
- `mt`: run the multi-threaded DPI engine

Because it is a CLI tool, there is no Swagger UI.

## Demo Setup

From the project root:

```bash
cd /Users/aashishkumar/Packet_analyzer
mvn clean package
```

This produces:

```bash
target/packet-analyzer-1.0-SNAPSHOT.jar
```

## Fast Demo Flow

### 1. Show the project structure

Say:

`This is a pure Java project packaged with Maven. The core logic is split into IO, parsing, inspection, rules, and engine layers.`

Important files to show:

- [`pom.xml`](/Users/aashishkumar/Packet_analyzer/pom.xml)
- [`README.md`](/Users/aashishkumar/Packet_analyzer/README.md)
- [`DpiApplication.java`](/Users/aashishkumar/Packet_analyzer/src/main/java/com/packetanalyzer/dpi/cli/DpiApplication.java)
- [`PcapReader.java`](/Users/aashishkumar/Packet_analyzer/src/main/java/com/packetanalyzer/dpi/io/PcapReader.java)
- [`PacketParser.java`](/Users/aashishkumar/Packet_analyzer/src/main/java/com/packetanalyzer/dpi/parse/PacketParser.java)
- [`SniExtractor.java`](/Users/aashishkumar/Packet_analyzer/src/main/java/com/packetanalyzer/dpi/inspect/SniExtractor.java)
- [`SimpleDpiEngine.java`](/Users/aashishkumar/Packet_analyzer/src/main/java/com/packetanalyzer/dpi/engine/SimpleDpiEngine.java)
- [`MultithreadedDpiEngine.java`](/Users/aashishkumar/Packet_analyzer/src/main/java/com/packetanalyzer/dpi/engine/MultithreadedDpiEngine.java)

### 2. Run packet analysis mode

Command:

```bash
java -jar target/packet-analyzer-1.0-SNAPSHOT.jar analyze test_dpi.pcap 3
```

What to say:

`This mode parses raw packets from a PCAP file and prints Ethernet, IP, TCP, and UDP details. It demonstrates binary parsing and protocol decoding in Java.`

What viewers should notice:

- decoded MAC addresses
- source and destination IPs
- ports and TCP flags
- payload preview

### 3. Run single-threaded DPI mode

Command:

```bash
java -jar target/packet-analyzer-1.0-SNAPSHOT.jar simple test_dpi.pcap filtered_simple.pcap --block-domain youtube
```

What to say:

`This mode tracks flows using five-tuples, extracts domain names from TLS ClientHello packets, classifies traffic, and blocks packets that match the rule set.`

What viewers should notice:

- blocked traffic log lines
- packet counts
- application breakdown
- generated output PCAP

### 4. Run multi-threaded DPI mode

Command:

```bash
java -jar target/packet-analyzer-1.0-SNAPSHOT.jar mt test_dpi.pcap filtered_mt.pcap --block-app YouTube --lbs 2 --fps 2
```

What to say:

`This mode uses multiple worker threads to distribute packet processing while preserving flow consistency with five-tuple hashing.`

What viewers should notice:

- load balancer and fast-path worker stats
- forwarded vs dropped counts
- per-application traffic summary
- detected domains and SNI values

## 2-Minute Interview Script

You can say this almost directly:

`This project is a Java-based deep packet inspection engine. It reads PCAP files, parses Ethernet, IPv4, TCP, and UDP packets, extracts TLS SNI and HTTP Host values to identify application traffic, then applies filtering rules based on IP, domain, or application type. I implemented both a single-threaded and a multi-threaded version. The multi-threaded version uses worker queues and flow hashing so packets from the same connection stay on the same processing path. I packaged it as a Maven-based Java project with a runnable jar and a CLI entry point for analysis and filtering workflows.`

## Best Things To Highlight On Resume Or To Reviewers

- low-level binary parsing in Java
- protocol-level networking knowledge
- TLS SNI inspection
- CLI application design
- concurrency with worker queues
- packet classification and filtering
- Maven packaging and runnable jar delivery

## If Someone Asks “Where Is Swagger?”

Use this answer:

`This project is not a web API, so there is no Swagger. It is a command-line network analysis tool. The main deliverable is the runnable jar and the processing/reporting output from PCAP files.`

## If You Want A Cleaner Live Demo

Use these exact commands:

```bash
mvn clean package
java -jar target/packet-analyzer-1.0-SNAPSHOT.jar analyze test_dpi.pcap 1
java -jar target/packet-analyzer-1.0-SNAPSHOT.jar mt test_dpi.pcap demo_output.pcap --block-app YouTube --lbs 2 --fps 2
```

That gives:

- one short parsing example
- one full DPI example
- one generated output file

## Optional Viewer Walkthrough

If you want to open code while explaining, use this order:

1. [`DpiApplication.java`](/Users/aashishkumar/Packet_analyzer/src/main/java/com/packetanalyzer/dpi/cli/DpiApplication.java)
2. [`PcapReader.java`](/Users/aashishkumar/Packet_analyzer/src/main/java/com/packetanalyzer/dpi/io/PcapReader.java)
3. [`PacketParser.java`](/Users/aashishkumar/Packet_analyzer/src/main/java/com/packetanalyzer/dpi/parse/PacketParser.java)
4. [`SniExtractor.java`](/Users/aashishkumar/Packet_analyzer/src/main/java/com/packetanalyzer/dpi/inspect/SniExtractor.java)
5. [`MultithreadedDpiEngine.java`](/Users/aashishkumar/Packet_analyzer/src/main/java/com/packetanalyzer/dpi/engine/MultithreadedDpiEngine.java)

## Expected Outcome

After the demo, the viewer should understand that:

- this is a complete Java project
- it solves a real systems/networking problem
- it demonstrates parsing, concurrency, and rule-based filtering
- it is runnable locally with a packaged jar
