# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Quick Start (Development)

```bash
# 1. Set up web UI credentials (export environment variables)
export WEB_USERNAME=admin
export WEB_PASSWORD=your_password_here
export WEB_PORT=4167
export WEB_BIND=127.0.0.1

# 2. Run in separate terminals:

# Terminal 1: Honeypot
sudo ruby honeypot.rb

# Terminal 2: Web UI (uses environment variables above)
ruby web_ui.rb

# Access web UI at: http://localhost:4167
# Honeypot ports: 1-10000 (Nmap top 200 by default)
```

**Note:** For development, you can also create a `.env` file locally (not committed to git) and load it with `export $(cat .env | xargs)` before running `web_ui.rb`. However, production uses systemd environment management.

### Quick Start (Production on Debian 13)

```bash
# 1. Install system dependencies (one-time setup)
sudo apt-get update
sudo apt-get install -y ruby ruby-dev build-essential git nginx certbot python3-certbot-nginx fail2ban cron
sudo gem install sinatra -v '~> 4.0' puma -v '~> 6.0' rackup -v '~> 2.0' json -v '~> 2.7'

# 2. Clone repository to /opt/honeypot
cd /opt
git clone <repo-url> honeypot
cd honeypot

# 3. Run deployment (sets up systemd, nginx, SSL)
sudo rake deploy

# Access web UI at: https://honeypot.officemsoft.com
# Services managed by systemd
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

### Running in Development

In development, run both processes manually in separate terminals:

```bash
# Terminal 1: Honeypot (needs root/sudo for ports < 1024)
sudo ruby honeypot.rb

# Terminal 2: Web UI (runs as regular user)
ruby web_ui.rb
```

### Running in Production

In production (Debian 13), use systemd services:

```bash
# Check status
sudo systemctl status honeypot.service
sudo systemctl status honeypot-web.service

# View logs
sudo journalctl -u honeypot.service -f
sudo journalctl -u honeypot-web.service -f

# Restart services
sudo systemctl restart honeypot.service
sudo systemctl restart honeypot-web.service
```

The honeypot service runs as the `honeypot` user with `CAP_NET_BIND_SERVICE` capability, allowing it to bind privileged ports without running as root.

### Web UI

The honeypot includes a web-based control panel for easy configuration and monitoring.

**Features:**
- Real-time dashboard with port statistics
- Live connection log (last 50 connections)
- Configuration forms for runtime settings
- Quick scenario presets (cloud, datacenter, hybrid)
- Basic authentication for security

**Access:**
- Development: `http://localhost:4167` (credentials via environment variables)
- Production: `https://honeypot.officemsoft.com` (credentials in `/etc/honeypot/env`)

**Configuration:**
- Development: Set `WEB_USERNAME`, `WEB_PASSWORD`, `WEB_PORT`, `WEB_BIND` environment variables
- Production: Managed by systemd via `/etc/honeypot/env` (EnvironmentFile)

**Security:**
- Basic HTTP authentication
- Runs as non-root user (separate from honeypot process)
- Communicates with honeypot via Unix socket
- Production: nginx with HTTPS + IP whitelist + fail2ban

## Architecture Overview

This is a network honeypot application designed to simulate **truly ephemeral ports** that change state between Nmap scans.

**Two-Process Architecture:**
```
┌─────────────────────────────────────┐
│  Process 1: Honeypot                │
│  - honeypot.rb                      │
│  - Runs as 'honeypot' user          │
│  - CAP_NET_BIND_SERVICE capability  │
│  - Binds to ports 1-65535           │
│  - Unix socket API: /tmp/honeypot.sock │
└──────────────┬──────────────────────┘
               │ Unix Socket IPC
┌──────────────┴──────────────────────┐
│  Process 2: Web UI                  │
│  - web_ui.rb (Sinatra + Puma)       │
│  - Runs as 'honeypot' user          │
│  - HTTP server on port 4167         │
│  - Basic authentication             │
│  - nginx reverse proxy (production) │
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
├── honeypot.rb          # Main honeypot process
├── web_ui.rb            # Web UI process
├── lib/
│   └── honeypot_client.rb  # Unix socket client library
├── views/
│   ├── dashboard.erb    # Dashboard page template
│   ├── settings.erb     # Settings page template
│   └── error.erb        # Error page template
├── test/                # Test suite
│   ├── unit/
│   └── integration/
├── deploy.sh            # Production deployment script
├── update.sh            # Quick update script
├── Gemfile              # Ruby dependencies
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

### Testing

The project includes a comprehensive test suite using Minitest:

**Run all tests:**
```bash
bundle exec rake test
```

**Test structure:**
```
test/
├── test_helper.rb          # Shared test setup and utilities
├── unit/
│   ├── test_honeypot.rb         # Honeypot class unit tests
│   └── test_honeypot_client.rb  # IPC client unit tests
└── integration/
    ├── test_ipc_communication.rb # Socket communication tests
    └── test_web_ui.rb            # Web UI integration tests
```

**Key test coverage:**
- Port rotation logic and state management
- IPC protocol and Unix socket communication
- File descriptor limit validation
- Configuration parsing and validation
- Web UI authentication and endpoints
- Connection logging and history tracking

### Deployment

For production deployment on a VPS or cloud server:

**Prerequisites (install first):**
```bash
# System packages
sudo apt-get update
sudo apt-get install -y ruby ruby-dev build-essential git nginx certbot python3-certbot-nginx fail2ban cron

# Ruby gems (system-wide)
sudo gem install sinatra -v '~> 4.0' --conservative
sudo gem install puma -v '~> 6.0' --conservative
sudo gem install rackup -v '~> 2.0' --conservative
sudo gem install json -v '~> 2.7' --conservative
```

**Deployment with Rake:**
```bash
# Clone to /opt/honeypot
cd /opt
sudo git clone <repo-url> honeypot
cd honeypot

# Full deployment (first time)
sudo rake deploy

# Quick update (pull code, restart services)
sudo rake update

# Check status
sudo rake status
```

**What `rake deploy` does:**
- Validates prerequisites are installed
- Creates honeypot system user
- Sets up systemd services with CAP_NET_BIND_SERVICE
- Configures nginx reverse proxy with SSL
- Obtains Let's Encrypt certificates
- Sets up automatic SSL renewal
- Configures fail2ban for web UI protection
- Creates necessary directories and permissions

**Security recommendations:**
- Run honeypot as dedicated user with minimal privileges
- Use strong passwords in `.env`
- Configure nginx with HTTPS (Let's Encrypt)
- Restrict web UI access by IP (firewall or nginx allow lists)
- Enable log rotation to prevent disk filling
- Monitor system resources (CPU, memory, file descriptors)
- Regular security updates for Ruby and dependencies

### Troubleshooting

**"Too many open files" error:**
```bash
# Check current limit
ulimit -n

# Increase limit temporarily
ulimit -n 66000

# For systemd service, add to unit file:
[Service]
LimitNOFILE=66000

# Or use preset with fewer ports:
ruby honeypot.rb --preset nmap-top-200
```

**Honeypot won't bind to privileged ports (<1024):**
```bash
# Run as root
sudo ruby honeypot.rb

# Or use only high ports
ruby honeypot.rb --preset high
```

**Web UI can't connect to honeypot:**
```bash
# Check if honeypot is running
ps aux | grep honeypot.rb

# Check if Unix socket exists
ls -la /tmp/honeypot.sock

# Check socket permissions (should be 0666)
# If wrong, honeypot will recreate on restart
```

**Rotation not happening:**
- Check logs for rotation interval setting
- Verify rotation thread is running (logs show [ROTATION] messages)
- Ensure enough rotatable ports (well-known ports never rotate)
- Check if file descriptor limit prevented binding new ports

**Web UI shows authentication error:**
- Verify `.env` file exists and has correct credentials
- Check `WEB_USERNAME` and `WEB_PASSWORD` are set
- Try default credentials: admin / change_me
- Restart web UI process after changing `.env`

**High CPU usage:**
- Normal during active scans (many connection threads)
- Reduce rotation frequency: `-t 30` (30 second intervals)
- Use fewer ports: `--preset nmap-top-200`
- Check for connection floods (review logs for source IPs)

### Development

**Project structure:**
- `honeypot.rb` - Main application (1300+ lines)
- `web_ui.rb` - Sinatra web interface
- `lib/` - Shared libraries and client code
- `views/` - ERB templates for web UI
- `test/` - Test suite
- `CLAUDE.md` - AI assistant documentation (this file)

**Making changes:**
1. Run tests before changes: `bundle exec rake test`
2. Make your modifications
3. Run tests after changes
4. Test manually with both processes running
5. Check logs for any errors or warnings

**Adding new protocol handlers:**
See existing handlers in honeypot.rb (lines 523-1048) as examples. Each handler:
- Receives client socket, port, and peer info
- Sends appropriate banner/response
- Optionally handles multi-line protocols
- Logs interactions for monitoring

**Modifying IPC API:**
1. Add new action handler in `start_unix_socket_server` (honeypot.rb:1142-1269)
2. Add corresponding method in `HoneypotClient` (lib/honeypot_client.rb)
3. Update web UI to use new endpoint (web_ui.rb)
4. Add integration test for new API call

### Ruby Version & Dependencies

- **Development**: Ruby 3.2+ (any version)
- **Production**: System Ruby on Debian 13 (Ruby 3.3+)
- **Dependencies**: Installed system-wide via `gem install`, no bundler required in production
  - sinatra ~> 4.0
  - puma ~> 6.0
  - rackup ~> 2.0
  - json ~> 2.7