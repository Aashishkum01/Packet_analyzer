# LinkedIn / Portfolio Description

## Short Version

Built a Java-based deep packet inspection project that reads PCAP files, parses Ethernet/IP/TCP/UDP packets, extracts TLS SNI and HTTP Host data, classifies application traffic, and filters packets using configurable blocking rules. Includes both single-threaded and multi-threaded processing modes, packaged as a runnable Maven project.

## Medium Version

I built a Java-only deep packet inspection and packet analysis project focused on offline network traffic processing. The application reads PCAP capture files, parses low-level packet headers, extracts application-identifying data such as TLS SNI and HTTP Host headers, and classifies flows into services like YouTube, GitHub, Spotify, and others. It supports blocking by IP, domain, and application type, and writes filtered traffic back to a new PCAP file.

The project includes both a single-threaded pipeline for clarity and a multi-threaded pipeline that uses worker queues and five-tuple hashing to keep packets from the same flow on the same processing path. It is packaged as a Java 17 Maven project with a runnable jar and CLI entry point, making it easy to demo locally.

## Project Caption

Java Deep Packet Inspection Engine | PCAP Parsing | TLS SNI Extraction | Multithreaded Packet Processing

## Suggested Post Text

Finished converting my packet analyzer / DPI project into a complete Java-only codebase.

The project reads PCAP files, parses packet headers, extracts TLS SNI and HTTP Host values, classifies traffic by application, and filters traffic using configurable rules. I also implemented a multi-threaded processing pipeline using queue-based workers and flow hashing to preserve per-connection consistency.

Tech used: Java 17, Maven, binary parsing, TCP/IP protocol handling, concurrency, CLI tooling.
