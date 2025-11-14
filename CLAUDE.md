# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Quick Start

```bash
# 1. Install dependencies
bundle install

# 2. Set up web UI credentials
cp .env.example .env
# Edit .env and set WEB_USERNAME and WEB_PASSWORD

# 3. Run everything with Foreman
foreman start

# Access web UI at: http://localhost:4167
# Honeypot ports: 1-10000 (Nmap top 200 by default)
```

### Running the Honeypot

**With Foreman (recommended):**
```bash
foreman start                    # Runs both honeypot and web UI
```

**Manually (separate terminals):**
```bash
# Terminal 1: Honeypot (needs root for ports < 1024)
sudo ruby honeypot.rb

# Terminal 2: Web UI (runs as regular user)
ruby web_ui.rb
```

**Command-line options (honeypot.rb):**
```bash
# Run with default settings (Nmap top 200 ports)
ruby honeypot.rb

# Run with Nmap port presets
ruby honeypot.rb --preset nmap-top-200
ruby honeypot.rb --preset nmap-top-1000
ruby honeypot.rb --preset all
ruby honeypot.rb --preset high    # Ports 1024-65535
ruby honeypot.rb --preset common  # Ports 1-1024

# Run with custom port range
ruby honeypot.rb -r 8000:9000

# Run with custom bind IP
ruby honeypot.rb -i 192.168.1.100

# Run with custom open/filtered port percentages
ruby honeypot.rb -o 50 -f 30

# Run with custom port rotation interval
ruby honeypot.rb -t 5  # Rotate ports every 5 seconds

# Combine options
ruby honeypot.rb --preset nmap-top-200 -o 80 -f 10 -t 15

# Show help
ruby honeypot.rb -h
```

### Running as Root vs Non-Root
- As root: Can bind to all ports including privileged ports (< 1024)
- As non-root: Will skip privileged ports and only bind to ports >= 1024

### Web UI

The honeypot includes a web-based control panel for easy configuration and monitoring.

**Features:**
- Real-time dashboard with port statistics
- Live connection log (last 50 connections)
- Configuration forms for runtime settings
- Quick scenario presets (cloud, datacenter, hybrid)
- Basic authentication for security

**Access:**
- URL: `http://localhost:4167` (or your server IP)
- Default credentials: admin / change_me (set in `.env`)

**Security:**
- Basic HTTP authentication
- Runs as non-root user (separate from honeypot process)
- Communicates with honeypot via Unix socket
- For public deployment: Use nginx with HTTPS + IP whitelist

## Architecture Overview

This is a network honeypot application designed to simulate **truly ephemeral ports** that change state between Nmap scans.

**Two-Process Architecture:**
```
┌─────────────────────────────────────┐
│  Process 1: Honeypot (root)         │
│  - honeypot.rb                      │
│  - Binds to ports 1-65535           │
│  - Unix socket API server           │
│  - /tmp/honeypot.sock               │
└──────────────┬──────────────────────┘
               │ Unix Socket IPC
┌──────────────┴──────────────────────┐
│  Process 2: Web UI (non-root)       │
│  - web_ui.rb (Sinatra + Puma)       │
│  - HTTP server on port 4167         │
│  - Basic authentication             │
└─────────────────────────────────────┘
```

**Components:**

### Core Class: Honeypot
Located in `honeypot.rb:7-1107`, handles:
- **Dynamic Port Rotation**: Ports continuously rotate between bound and unbound states
  - **Bound ports**: Listening sockets that respond as "open" or "filtered" to Nmap
  - **Unbound ports**: Not listening, OS sends RST (Nmap sees as "closed")
  - **Rotation cycle**: Every N seconds (default: 10s), random ports are bound/unbound
  - **Well-known ports**: Always stay bound for realism (SSH, HTTP, MySQL, etc.)
- **Port Behaviors**: Simulates three types of port responses:
  - **Open ports**: Accept connections and respond with service-specific banners
  - **Filtered ports**: Accept connections but don't respond (simulating packet drops)
  - **Closed ports**: Unbound ports where OS sends RST packets
- **Network Detection**: Automatically detects available network interfaces
- **Connection Handling**: Multi-threaded architecture with one thread per bound port
- **File Descriptor Management**: Checks system limits and warns about potential issues

### Key Methods

**Initialization & Lifecycle:**
- `initialize` (honeypot.rb:31-60): Sets up configuration, logging, and signal handlers
- `start` (honeypot.rb:117-142): Main loop that manages the honeypot lifecycle
- `get_preset_ports` (honeypot.rb:62-78): Returns port list based on preset name
- `check_file_descriptor_limit` (honeypot.rb:80-115): Validates system can handle port count

**Port Rotation System:**
- `bind_initial_ports` (honeypot.rb:162-233): Initial port binding with well-known ports
- `start_port_rotation_manager` (honeypot.rb:286-303): Background thread for port rotation
- `rotate_ports` (honeypot.rb:305-356): Rotates 30-50% of non-well-known ports each cycle
- `bind_port` (honeypot.rb:235-261): Binds a TCP server to a port and starts listener thread
- `unbind_port` (honeypot.rb:263-284): Closes server socket and stops listening on a port

**Connection Handling:**
- `handle_port` (honeypot.rb:358-407): Main listener loop for each bound port
- `handle_open_connection` (honeypot.rb:409-440): Handles normal open port responses
- `handle_filtered_connection` (honeypot.rb:442-461): Simulates filtered ports (accept but don't respond)
- `handle_protocol_interaction` (honeypot.rb:483-521): Routes to protocol-specific handlers

**Protocol Handlers:**
- `generate_banner` (honeypot.rb:1050-1081): Returns service-specific banners for common ports
- `handle_http` (honeypot.rb:523-549): HTTP/HTTPS protocol handler
- `handle_ssh` (honeypot.rb:551-568): SSH protocol handler
- `handle_ftp` (honeypot.rb:570-596): FTP protocol handler
- `handle_smtp` (honeypot.rb:598-627): SMTP protocol handler
- And 20+ more protocol-specific handlers for MySQL, PostgreSQL, Redis, Telnet, etc.

### Threading Model
- **Main thread**: Control loop that sleeps and performs thread cleanup
- **Rotation thread**: Background thread that rotates ports every N seconds
- **Listener threads**: One per bound port (dynamically created/destroyed during rotation)
- **Connection threads**: Spawned for each incoming connection
- **Thread-safe port rotation**: Uses mutex to prevent race conditions during bind/unbind
- **Cleanup mechanism**: Regularly removes dead threads from thread pool

### Configuration Options
The honeypot accepts command-line parameters parsed at honeypot.rb:1113-1176:

**Port Selection:**
- `-p, --preset PRESET`: Port preset (nmap-top-200, nmap-top-1000, all, high, common)
- `-r, --range START:END`: Custom port range (e.g., 8000:9000)
- Default: Nmap top 200 ports (prevents file descriptor issues)

**Network:**
- `-i, --ip IP`: Bind IP address (default: 0.0.0.0)

**Behavior:**
- `-o, --open PERCENT`: Percentage of ports to bind (default: 70%)
- `-f, --filtered PERCENT`: Percentage of bound ports that hang without responding (default: 20%)
- `-t, --rotation SECONDS`: Port rotation interval in seconds (default: 10)

**Other:**
- `-h, --help`: Show help message

### How Dynamic Port Rotation Works

The honeypot implements **truly ephemeral ports** that change state between Nmap scans:

**Port State Model:**
- **Bound ports**: TCP servers actively listening on these ports
  - Respond to Nmap as "open" (send banner) or "filtered" (accept but don't respond)
  - Percentage configured via `-o` option (default: 70%)
- **Unbound ports**: No listener, operating system handles these
  - OS sends RST packets to connection attempts
  - Nmap reports these as "closed"
  - Percentage: 100 - open_percent (default: 30%)

**Rotation Cycle:**
1. Every rotation interval (default: 10 seconds)
2. Select 30-50% of rotatable bound ports (minimum 30 ports for Nmap top 200)
3. Unbind those ports (close TCP server, stop listening)
4. Bind the same number of random unbound ports
5. Result: Port states genuinely change, Nmap sees different results on each scan

**Well-Known Ports:**
Always stay bound for realism (defined in honeypot.rb:164-187):
- SSH (22), HTTP (80), HTTPS (443), FTP (21), SMTP (25)
- MySQL (3306), PostgreSQL (5432), Redis (6379), MongoDB (27017)
- And 13+ more common service ports

These well-known ports never rotate to maintain realistic service fingerprints.

**Why This Matters:**
- Traditional honeypots have static port states
- This honeypot simulates real-world ephemeral ports (Docker, Kubernetes, microservices)
- Automated scanners see genuinely different port states on each scan
- Perfect for testing Nmap automation that must handle changing port landscapes

### Port Presets

Pre-configured port lists to avoid file descriptor limits:

- **nmap-top-200** (default): 200 most commonly scanned ports by Nmap
- **nmap-top-1000**: Top 1000 Nmap ports (placeholder implementation currently)
- **all**: All ports 1-65535 (requires: `ulimit -n 66000`)
- **high**: High ports 1024-65535 (non-privileged)
- **common**: Common ports 1-1024 (requires root)

The default preset (nmap-top-200) prevents "too many open files" errors on most systems.

### Logging and Monitoring

The honeypot provides comprehensive logging of all events:

**Log Levels:**
- **INFO**: Startup, configuration, rotation events, connections accepted
- **DEBUG**: Detailed protocol interactions, bind/unbind events
- **WARN**: File descriptor warnings, permission issues
- **ERROR**: Connection errors, unexpected exceptions

**Key Log Messages:**
- `[BIND]`: Port bound and listener thread started
- `[UNBIND]`: Port unbound and listener thread stopped
- `[ROTATION]`: Port rotation cycle with statistics
- `[ACCEPT]`: New connection accepted from scanner
- `[OPEN]`: Port responding normally with banner
- `[FILTERED]`: Port simulating filtered behavior (hanging)
- `[CLOSE]`: Connection closed with duration
- `[FAST-CLOSE]`: Scanner disconnected before peeraddr could be obtained

**Rotation Statistics:**
Each rotation cycle logs:
- Number of ports unbound (changed from open to closed)
- Number of ports bound (changed from closed to open)
- Percentage of rotatable ports changed
- Total current bound/unbound port counts

Example:
```
[11:23:45] INFO: [ROTATION] Cycled 42 closed, 42 opened (30% of rotatable). Total: 140 bound, 60 unbound
```

### File Structure

```
honeypot/
├── honeypot.rb          # Main honeypot process (root)
├── web_ui.rb            # Web UI process (non-root)
├── lib/
│   └── honeypot_client.rb  # Unix socket client library
├── views/
│   ├── dashboard.erb    # Dashboard page template
│   ├── settings.erb     # Settings page template
│   └── error.erb        # Error page template
├── Gemfile              # Ruby dependencies
├── Procfile             # Foreman process definitions
├── .env.example         # Environment variables template
├── .env                 # Your credentials (not in git)
└── CLAUDE.md           # This file
```

### Inter-Process Communication (IPC)

The honeypot and web UI communicate via Unix socket (`/tmp/honeypot.sock`):

**API Commands:**
- `get_status` - Current port counts, uptime, rotation stats
- `update_config` - Change rotation interval, open %, filtered %
- `get_connections` - Recent connection history
- `get_ports` - Currently bound/unbound port lists
- `rotate_now` - Trigger immediate port rotation
- `ping` - Health check

**Example (from web_ui.rb):**
```ruby
client = HoneypotClient.new
status = client.status
# => { ports_bound: 140, uptime: 3600, last_rotation: 12, ... }
```

### Ruby Version
Uses Ruby 3.4.7 as specified in `.tool-versions`