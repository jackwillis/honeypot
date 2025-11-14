# Honeypot - Dynamic Port Rotation Testing Tool

A network honeypot designed to simulate **truly ephemeral ports** that change state between scans. Perfect for testing security automation, Nmap scripts, and pentest tooling against realistic cloud-native infrastructure.

## Features

- **Dynamic Port Rotation**: Ports continuously rotate between open/filtered/closed states
- **Protocol Simulation**: 20+ protocol handlers (HTTP, SSH, FTP, MySQL, PostgreSQL, Redis, etc.)
- **Web UI**: Real-time dashboard and configuration interface
- **Secure Architecture**: Privilege-separated processes (honeypot runs as root, web UI as user)
- **Flexible Configuration**: Command-line options, web interface, and scenario presets

## Quick Start

```bash
# 1. Install dependencies
bundle install

# 2. Set up web UI credentials
cp .env.example .env
# Edit .env and change WEB_USERNAME and WEB_PASSWORD

# 3. Run both processes with Foreman
foreman start
```

**Access the Web UI:** `http://localhost:4167`
**Default credentials:** admin / change_me (as set in `.env`)

## Architecture

```
┌─────────────────────────────────┐
│  Process 1: Honeypot (root)     │
│  - Binds to ports 1-65535       │
│  - Unix socket API server       │
└──────────────┬──────────────────┘
               │ Unix Socket IPC
┌──────────────┴──────────────────┐
│  Process 2: Web UI (non-root)   │
│  - Sinatra on port 4167         │
│  - Basic authentication         │
└─────────────────────────────────┘
```

## Usage

### Running with Foreman (Recommended)

```bash
foreman start
```

### Running Manually (Two Terminals)

```bash
# Terminal 1: Honeypot (needs root for ports < 1024)
sudo ruby honeypot.rb

# Terminal 2: Web UI (runs as regular user)
ruby web_ui.rb
```

### Command-Line Options

```bash
# Port presets
ruby honeypot.rb --preset nmap-top-200       # Default, 200 most scanned ports
ruby honeypot.rb --preset nmap-top-1000      # Top 1000 ports
ruby honeypot.rb --preset all                # All ports 1-65535
ruby honeypot.rb --preset high               # High ports 1024-65535
ruby honeypot.rb --preset common             # Common ports 1-1024

# Custom port range
ruby honeypot.rb -r 8000:9000

# Configure behavior
ruby honeypot.rb -o 80 -f 10 -t 5
# -o: Open percentage (80%)
# -f: Filtered percentage (10%)
# -t: Rotation interval (5 seconds)

# Custom bind IP
ruby honeypot.rb -i 192.168.1.100
```

## Web UI Features

- **Dashboard**: Real-time stats, port counts, connection log
- **Settings**: Configure rotation interval, open %, filtered %
- **Quick Scenarios**: Apply presets for cloud/datacenter/hybrid testing
- **Auto-refresh**: Dashboard updates every 3 seconds

### Quick Scenarios

- **Cloud Native** (rotation: 5s, open: 80%, filtered: 15%)
  - Simulates AWS/GCP/Azure with fast-changing services
- **Datacenter** (rotation: 60s, open: 40%, filtered: 30%)
  - Traditional infrastructure with mostly static ports
- **Hybrid** (rotation: 15s, open: 60%, filtered: 20%)
  - Mix of cloud and legacy infrastructure

## How It Works

### Port State Model

- **Bound ports**: TCP servers actively listening
  - Respond to Nmap as "open" (send banner) or "filtered" (accept but don't respond)
- **Unbound ports**: No listener, OS sends RST
  - Nmap reports as "closed"

### Rotation Cycle

1. Every N seconds (default: 10)
2. Select 30-50% of rotatable bound ports
3. Unbind those ports (close TCP server)
4. Bind same number of random unbound ports
5. Result: Port states genuinely change between scans

### Well-Known Ports

These ports **always stay bound** for realism:
- SSH (22), HTTP (80), HTTPS (443), FTP (21), SMTP (25)
- MySQL (3306), PostgreSQL (5432), Redis (6379), MongoDB (27017)
- And 13+ more common service ports

## Security Considerations

### For Development/Local Testing

- Default setup is fine (Basic Auth + localhost)
- Web UI runs as non-root user

### For Public Deployment

**Required:**
- Use nginx as reverse proxy
- Enable HTTPS with Let's Encrypt
- Add IP whitelist (restrict to your office/VPN)
- Change default credentials in `.env`

**Example nginx config:**

```nginx
server {
    listen 443 ssl;
    server_name honeypot.yourcompany.com;

    ssl_certificate /etc/letsencrypt/live/honeypot.yourcompany.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/honeypot.yourcompany.com/privkey.pem;

    # IP whitelist
    allow 203.0.113.0/24;  # Your office IP range
    deny all;

    location / {
        proxy_pass http://127.0.0.1:4167;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Testing Your Automation

### Example: Test Nmap Automation

```bash
# Terminal 1: Start honeypot
foreman start

# Terminal 2: Run multiple scans
for i in {1..5}; do
  echo "Scan $i:"
  nmap -p 1-10000 localhost --open
  sleep 15  # Wait for rotation
done
```

You should see different port states on each scan due to rotation.

### Example: Test Service Detection

```bash
# Scan with service detection
nmap -p 22,80,443,3306,5432,6379 -sV localhost

# Should correctly identify:
# - SSH on 22
# - HTTP on 80
# - HTTPS on 443 (TLS handshake failure)
# - MySQL on 3306
# - PostgreSQL on 5432
# - Redis on 6379
```

## File Structure

```
honeypot/
├── honeypot.rb              # Main honeypot process (root)
├── web_ui.rb                # Web UI process (non-root)
├── lib/
│   └── honeypot_client.rb   # Unix socket client
├── views/
│   ├── dashboard.erb        # Dashboard template
│   ├── settings.erb         # Settings template
│   └── error.erb            # Error template
├── Gemfile                  # Ruby dependencies
├── Procfile                 # Foreman process definitions
├── .env.example             # Environment variables template
├── .env                     # Your credentials (not in git)
├── CLAUDE.md                # Developer documentation
└── README.md                # This file
```

## API Endpoints

The web UI exposes JSON endpoints for programmatic access:

```bash
# Get current status
curl -u admin:change_me http://localhost:4167/api/status

# Get recent connections
curl -u admin:change_me http://localhost:4167/api/connections?limit=100

# Get current port states
curl -u admin:change_me http://localhost:4167/api/ports

# Health check
curl -u admin:change_me http://localhost:4167/health
```

## Troubleshooting

### "Connection refused" on web UI

Make sure both processes are running:
```bash
# Check if honeypot is running
ls -la /tmp/honeypot.sock

# If not, start it
ruby honeypot.rb
```

### "Too many open files" error

Increase file descriptor limit:
```bash
ulimit -n 10000
ruby honeypot.rb --preset nmap-top-200
```

### Ports < 1024 not binding

Run honeypot as root:
```bash
sudo ruby honeypot.rb
```

Or use Linux capabilities (Linux only):
```bash
sudo setcap 'cap_net_bind_service=+ep' $(which ruby)
ruby honeypot.rb
```

## Testing

The project includes a comprehensive test suite using **minitest** and **mocha**.

### Running Tests

```bash
# Run all tests
bundle exec rake test

# Run only unit tests (fast, mocked I/O)
bundle exec rake test_unit

# Run only integration tests (real Unix sockets)
bundle exec rake test_integration

# Run specific test file
ruby -Ilib:test test/unit/test_honeypot.rb
```

### Test Structure

```
test/
├── test_helper.rb              # Setup, helpers, fixtures
├── unit/
│   ├── test_honeypot.rb        # Honeypot class (15 tests)
│   └── test_honeypot_client.rb # IPC client (11 tests)
└── integration/
    ├── test_ipc_communication.rb  # Unix socket IPC (13 tests)
    └── test_web_ui.rb             # Sinatra routes (30+ tests)
```

**Total: 69+ tests** covering:
- Port rotation logic
- Configuration updates
- IPC communication (Unix sockets)
- Web UI routes and authentication
- API endpoints
- Error handling

## Production Deployment (Debian 13)

### Prerequisites

Install system dependencies (Ruby, build tools, nginx, SSL):

```bash
# Update package lists
sudo apt-get update

# Install required packages
sudo apt-get install -y \
  ruby \
  ruby-dev \
  build-essential \
  git \
  nginx \
  certbot \
  python3-certbot-nginx \
  fail2ban \
  cron \
  sqlite3

# Install bundler (only system gem needed)
sudo gem install bundler
```

**Note:** We use bundler to install gems to `vendor/bundle` instead of system-wide installation. This keeps gems isolated to the project.

### Deployment Steps

```bash
# 1. Clone repository to /opt/honeypot
sudo mkdir -p /opt
cd /opt
sudo git clone <repo-url> honeypot
cd honeypot

# 2. Run full deployment (installs gems, sets up systemd, nginx, SSL, etc.)
sudo rake deploy

# The deploy task will:
# - Install gems via bundler to vendor/bundle
# - Create honeypot system user
# - Set up systemd services
# - Configure nginx with SSL
# - Create credentials at /etc/honeypot/credentials
```

**Accessing the Web UI:**
- URL: `https://honeypot.officemsoft.com`
- View credentials: `sudo cat /etc/honeypot/credentials`
- Change password: Edit `/etc/honeypot/credentials` and restart services

### Deployment Tasks

```bash
# Full deployment (first time)
sudo rake deploy

# Quick update (pull code, restart services)
sudo rake update

# Check deployment status
sudo rake status
```

### What `rake deploy` Does

- Installs gems via bundler to `vendor/bundle` (as honeypot user)
- Creates FHS-compliant directories (`/etc/honeypot`, `/var/lib/honeypot`, `/var/log/honeypot`)
- Creates `honeypot` system user
- Sets up systemd services with CAP_NET_BIND_SERVICE and RuntimeDirectory
- Configures nginx reverse proxy with SSL
- Obtains Let's Encrypt certificates
- Sets up automatic SSL renewal (cron)
- Configures fail2ban for web UI protection
- Generates secure credentials at `/etc/honeypot/credentials`

### Managing Services

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

## Requirements

- Ruby 3.2+ (3.3+ recommended for production)
- Unix-like OS (Linux, macOS, BSD)

## License

See LICENSE file for details.

## Contributing

This is an internal tool for testing pentest automation. For questions or issues, contact the security team.
