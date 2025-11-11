# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Running the Honeypot
```bash
# Run with default settings
ruby honeypot.rb

# Run with custom port range
ruby honeypot.rb -r 8000:9000

# Run with custom bind IP
ruby honeypot.rb -i 192.168.1.100

# Run with custom open/filtered port percentages
ruby honeypot.rb -o 50 -f 30

# Show help
ruby honeypot.rb -h
```

### Running as Root vs Non-Root
- As root: Can bind to all ports including privileged ports (< 1024)
- As non-root: Will skip privileged ports and only bind to ports >= 1024

## Architecture Overview

This is a network honeypot application designed to simulate open and filtered ports to detect and log port scanning attempts. The application consists of a single Ruby file (`honeypot.rb`) with the following key components:

### Core Class: Honeypot
Located in `honeypot.rb:5-238`, handles:
- **Port Binding**: Dynamically binds to random ports within a specified range
- **Port Behaviors**: Simulates three types of port responses:
  - Open ports: Accept connections and respond with service-specific banners
  - Filtered ports: Accept connections but don't respond (simulating packet drops)
  - Closed ports: Not bound at all
- **Network Detection**: Automatically detects available network interfaces
- **Connection Handling**: Multi-threaded architecture with one thread per port

### Key Methods
- `initialize` (honeypot.rb:6-19): Sets up configuration and signal handlers
- `start` (honeypot.rb:21-38): Main loop that manages the honeypot lifecycle
- `bind_random_ports` (honeypot.rb:58-80): Binds to ports based on configured percentages
- `handle_port` (honeypot.rb:132-158): Manages incoming connections per port
- `generate_banner` (honeypot.rb:187-212): Returns service-specific banners for common ports

### Threading Model
- One main thread for the control loop
- One listener thread per bound port
- Spawns additional threads for handling individual connections
- Includes cleanup mechanism for dead threads

### Configuration Options
The honeypot accepts command-line parameters parsed at honeypot.rb:241-268:
- Port range (default: 1-10000)
- Bind IP (default: 0.0.0.0)
- Open port percentage (default: 70%)
- Filtered port percentage (default: 20%)

### Ruby Version
Uses Ruby 3.4.7 as specified in `.tool-versions`