# DPI Engine - Java Project

This repository is a Java-only packet analyzer and deep packet inspection project. The old C++ implementation has been removed so the repo presents as a standard Java codebase suitable for portfolio and resume use.

## Project Modes

- `analyze`: decode packets from a PCAP file and print protocol details
- `simple`: run the single-threaded DPI pipeline and write filtered output
- `mt`: run the multi-threaded DPI pipeline with load balancers and fast-path workers

## Stack

- Java 17
- Maven
- No external runtime dependencies

## Structure

```text
packet_analyzer/
├── pom.xml
├── README.md
├── test_dpi.pcap
└── src/main/java/com/packetanalyzer/dpi/
    ├── cli/
    ├── engine/
    ├── inspect/
    ├── io/
    ├── model/
    ├── parse/
    ├── rules/
    └── util/
```

## Main Entry Points

- `com.packetanalyzer.dpi.cli.DpiApplication`
- `com.packetanalyzer.dpi.cli.PacketAnalyzerCli`
- `com.packetanalyzer.dpi.cli.SimpleDpiCli`
- `com.packetanalyzer.dpi.cli.MultithreadedDpiCli`

## Why This Project Matters

This project demonstrates practical systems and networking skills in Java rather than typical CRUD application work. It focuses on:

- binary protocol parsing
- traffic classification from packet contents
- flow-aware filtering logic
- concurrent processing design
- packaging a technical tool into a clean Java project

## Build

```bash
mvn clean package
```

This produces:

```bash
target/packet-analyzer-1.0-SNAPSHOT.jar
```

## Run

Analyze packets:

```bash
java -jar target/packet-analyzer-1.0-SNAPSHOT.jar analyze test_dpi.pcap 5
```

Single-threaded DPI:

```bash
java -jar target/packet-analyzer-1.0-SNAPSHOT.jar simple test_dpi.pcap filtered_simple.pcap --block-domain youtube
```

Multi-threaded DPI:

```bash
java -jar target/packet-analyzer-1.0-SNAPSHOT.jar mt test_dpi.pcap filtered_mt.pcap --block-app YouTube --lbs 2 --fps 2
```

## Demo For Reviewers

Use this short demo sequence:

```bash
mvn clean package
java -jar target/packet-analyzer-1.0-SNAPSHOT.jar analyze test_dpi.pcap 1
java -jar target/packet-analyzer-1.0-SNAPSHOT.jar mt test_dpi.pcap demo_output.pcap --block-app YouTube --lbs 2 --fps 2
```

This shows:

- decoded packet parsing
- application classification
- blocking behavior
- multi-threaded DPI reporting
- generated filtered output

## Features

- PCAP binary file parsing in Java
- Ethernet, IPv4, TCP, and UDP decoding
- TLS ClientHello SNI extraction
- HTTP Host header extraction
- DNS query extraction support
- flow tracking with five-tuples
- blocking by IP, domain, and application
- concurrent DPI processing with worker queues

## Resume Summary

This project demonstrates low-level protocol parsing, Java concurrency, CLI design, binary IO, and Maven-based packaging in a networking-focused application.

For interview/demo notes, see [`DEMO.md`](/Users/aashishkumar/Packet_analyzer/DEMO.md).
For resume bullets, see [`RESUME.md`](/Users/aashishkumar/Packet_analyzer/RESUME.md).
For LinkedIn/project text, see [`LINKEDIN.md`](/Users/aashishkumar/Packet_analyzer/LINKEDIN.md).

## Notes

- `test_dpi.pcap` is included as sample input
- filtering modes create new output PCAP files when run
- the default runnable jar entry point is `DpiApplication`
