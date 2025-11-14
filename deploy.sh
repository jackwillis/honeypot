#!/bin/bash
set -e

##############################################################################
# Honeypot Deployment Script for Debian 13
#
# This script is idempotent - safe to run multiple times.
# It sets up:
# - System Ruby and dependencies
# - nginx with Let's Encrypt SSL
# - Systemd services for honeypot and web UI
# - fail2ban protection for web UI
#
# Usage:
#   sudo ./deploy.sh
#
# Requirements:
#   - Debian 13
#   - Domain honeypot.officemsoft.com pointing to this server
#   - Ports 80, 443, 4167 accessible
##############################################################################

DOMAIN="honeypot.officemsoft.com"
APP_DIR="/opt/honeypot"
WEB_PORT="4167"
HONEYPOT_USER="honeypot"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root (use sudo)"
    exit 1
fi

log_info "Starting honeypot deployment for $DOMAIN..."

##############################################################################
# 1. Install System Dependencies
##############################################################################

log_info "Installing system dependencies..."

# Update package list
apt-get update -qq

# Install packages if not already installed
PACKAGES=(
    "ruby"
    "ruby-dev"
    "build-essential"
    "git"
    "nginx"
    "certbot"
    "python3-certbot-nginx"
    "fail2ban"
)

for pkg in "${PACKAGES[@]}"; do
    if ! dpkg -l | grep -q "^ii  $pkg "; then
        log_info "Installing $pkg..."
        apt-get install -y "$pkg" > /dev/null
    else
        log_info "$pkg already installed"
    fi
done

# Install bundler if not present
if ! gem list bundler -i > /dev/null 2>&1; then
    log_info "Installing bundler..."
    gem install bundler
else
    log_info "bundler already installed"
fi

# Install foreman if not present
if ! gem list foreman -i > /dev/null 2>&1; then
    log_info "Installing foreman..."
    gem install foreman
else
    log_info "foreman already installed"
fi

##############################################################################
# 2. Create Honeypot System User
##############################################################################

log_info "Creating honeypot system user..."

# Create honeypot user if it doesn't exist
if ! id "$HONEYPOT_USER" &>/dev/null; then
    useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin --comment "Honeypot Service User" "$HONEYPOT_USER"
    log_info "Created user $HONEYPOT_USER"
else
    log_info "User $HONEYPOT_USER already exists"
fi

##############################################################################
# 3. Set Up Application Directory
##############################################################################

log_info "Setting up application directory..."

if [ ! -d "$APP_DIR" ]; then
    log_warn "Application directory $APP_DIR does not exist!"
    log_info "Please git clone your repository to $APP_DIR first"
    exit 1
fi

cd "$APP_DIR"

# Add safe directory exception for git (in case we need to pull later)
if [ -d .git ]; then
    git config --global --add safe.directory "$APP_DIR" 2>/dev/null || true
fi

# Install Ruby dependencies
log_info "Installing Ruby gems..."

# Find bundle path (try multiple locations)
BUNDLE_PATH=$(which bundle 2>/dev/null)
if [ -z "$BUNDLE_PATH" ]; then
    # Try common gem bin paths
    for path in /usr/local/bin/bundle /var/lib/gems/*/bin/bundle /usr/lib/ruby/gems/*/bin/bundle; do
        if [ -x "$path" ]; then
            BUNDLE_PATH=$path
            break
        fi
    done
fi

if [ -z "$BUNDLE_PATH" ]; then
    log_warn "bundler not found in PATH, reinstalling..."
    gem install bundler
    BUNDLE_PATH=$(which bundle 2>/dev/null)
    if [ -z "$BUNDLE_PATH" ]; then
        log_error "Failed to install bundler"
        exit 1
    fi
fi

log_info "Using bundler at: $BUNDLE_PATH"

# Run bundle as root, then fix ownership
$BUNDLE_PATH config set --local deployment 'true'
$BUNDLE_PATH config set --local without 'development test'
$BUNDLE_PATH install --quiet

# Set ownership after bundle install
chown -R "$HONEYPOT_USER:$HONEYPOT_USER" "$APP_DIR"

# Create .env file if it doesn't exist
if [ ! -f "$APP_DIR/.env" ]; then
    log_info "Creating .env file..."
    if [ -f "$APP_DIR/.env.example" ]; then
        cp "$APP_DIR/.env.example" "$APP_DIR/.env"
        log_warn "Please edit $APP_DIR/.env and set WEB_USERNAME and WEB_PASSWORD"
    else
        cat > "$APP_DIR/.env" << EOF
WEB_USERNAME=admin
WEB_PASSWORD=change_me_$(openssl rand -hex 8)
EOF
        log_warn "Generated random password in $APP_DIR/.env - please review!"
    fi
    chown "$HONEYPOT_USER:$HONEYPOT_USER" "$APP_DIR/.env"
fi

# Create logs directory
mkdir -p "$APP_DIR/logs"
chown -R "$HONEYPOT_USER:$HONEYPOT_USER" "$APP_DIR/logs"

##############################################################################
# 4. Configure nginx
##############################################################################

log_info "Configuring nginx..."

NGINX_CONFIG="/etc/nginx/sites-available/honeypot"
NGINX_ENABLED="/etc/nginx/sites-enabled/honeypot"

# Create nginx configuration
cat > "$NGINX_CONFIG" << 'EOF'
# Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name honeypot.officemsoft.com;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name honeypot.officemsoft.com;

    # SSL certificates (managed by certbot)
    ssl_certificate /etc/letsencrypt/live/honeypot.officemsoft.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/honeypot.officemsoft.com/privkey.pem;

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Logging
    access_log /var/log/nginx/honeypot_access.log;
    error_log /var/log/nginx/honeypot_error.log;

    # Proxy to web UI
    location / {
        proxy_pass http://127.0.0.1:4167;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (if needed in future)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
EOF

# Enable site
if [ ! -L "$NGINX_ENABLED" ]; then
    ln -s "$NGINX_CONFIG" "$NGINX_ENABLED"
    log_info "Enabled nginx site"
fi

# Remove default nginx site if present
if [ -L "/etc/nginx/sites-enabled/default" ]; then
    rm "/etc/nginx/sites-enabled/default"
    log_info "Removed default nginx site"
fi

# Test nginx configuration
if nginx -t 2>/dev/null; then
    log_info "nginx configuration is valid"
else
    log_error "nginx configuration is invalid!"
    nginx -t
    exit 1
fi

##############################################################################
# 5. Set Up Let's Encrypt SSL
##############################################################################

log_info "Setting up Let's Encrypt SSL..."

if [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    log_info "Obtaining SSL certificate for $DOMAIN..."

    # Stop nginx temporarily
    systemctl stop nginx

    # Obtain certificate
    certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email

    if [ $? -eq 0 ]; then
        log_info "SSL certificate obtained successfully"
    else
        log_error "Failed to obtain SSL certificate"
        log_error "Make sure $DOMAIN points to this server and ports 80/443 are open"
        exit 1
    fi
else
    log_info "SSL certificate already exists for $DOMAIN"
fi

# Set up automatic renewal
if ! crontab -l 2>/dev/null | grep -q "certbot renew"; then
    log_info "Setting up automatic SSL renewal..."
    (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet --post-hook 'systemctl reload nginx'") | crontab -
fi

# Start nginx
systemctl enable nginx
systemctl start nginx
systemctl reload nginx

log_info "nginx is running with SSL"

##############################################################################
# 6. Create Systemd Services
##############################################################################

log_info "Creating systemd services..."

# Honeypot service (runs as honeypot user with CAP_NET_BIND_SERVICE)
cat > /etc/systemd/system/honeypot.service << EOF
[Unit]
Description=Network Honeypot with Dynamic Port Rotation
After=network.target

[Service]
Type=simple
User=$HONEYPOT_USER
WorkingDirectory=$APP_DIR
ExecStart=/usr/bin/ruby $APP_DIR/honeypot.rb --preset nmap-top-200
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Allow binding to privileged ports (< 1024) without running as root
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

# Security hardening
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$APP_DIR/logs /tmp

[Install]
WantedBy=multi-user.target
EOF

# Web UI service (runs as honeypot user)
cat > /etc/systemd/system/honeypot-web.service << EOF
[Unit]
Description=Honeypot Web UI
After=network.target honeypot.service

[Service]
Type=simple
User=$HONEYPOT_USER
WorkingDirectory=$APP_DIR
Environment="RACK_ENV=production"
ExecStart=/usr/bin/ruby $APP_DIR/web_ui.rb
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$APP_DIR/logs /tmp

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

# Enable and start services
log_info "Starting honeypot services..."

systemctl enable honeypot.service
systemctl enable honeypot-web.service

# Restart services (idempotent)
systemctl restart honeypot.service
systemctl restart honeypot-web.service

# Check status
if systemctl is-active --quiet honeypot.service; then
    log_info "honeypot.service is running"
else
    log_error "honeypot.service failed to start"
    systemctl status honeypot.service --no-pager
    exit 1
fi

if systemctl is-active --quiet honeypot-web.service; then
    log_info "honeypot-web.service is running"
else
    log_error "honeypot-web.service failed to start"
    systemctl status honeypot-web.service --no-pager
    exit 1
fi

##############################################################################
# 7. Configure fail2ban
##############################################################################

log_info "Configuring fail2ban..."

# Create fail2ban filter for nginx 401 responses
cat > /etc/fail2ban/filter.d/honeypot-web.conf << 'EOF'
[Definition]
failregex = ^<HOST> - .* ".*" 401 .*
ignoreregex =
EOF

# Create fail2ban jail
cat > /etc/fail2ban/jail.d/honeypot-web.conf << 'EOF'
[honeypot-web]
enabled = true
port = 443
filter = honeypot-web
logpath = /var/log/nginx/honeypot_access.log
maxretry = 5
findtime = 600
bantime = 3600
action = iptables-multiport[name=honeypot-web, port="80,443", protocol=tcp]
EOF

# Restart fail2ban
systemctl enable fail2ban
systemctl restart fail2ban

log_info "fail2ban is configured and running"

##############################################################################
# 8. Configure Firewall (UFW)
##############################################################################

log_info "Configuring firewall..."

if ! command -v ufw &> /dev/null; then
    apt-get install -y ufw > /dev/null
fi

# Configure UFW (idempotent)
ufw --force enable

# Allow SSH
ufw allow 22/tcp > /dev/null 2>&1 || true

# Allow HTTP/HTTPS for nginx
ufw allow 80/tcp > /dev/null 2>&1 || true
ufw allow 443/tcp > /dev/null 2>&1 || true

# Allow all TCP ports for honeypot
ufw allow 1:65535/tcp > /dev/null 2>&1 || true

log_info "Firewall configured"

##############################################################################
# 9. Final Checks
##############################################################################

log_info "Running final checks..."

# Check if domain resolves to this server
SERVER_IP=$(curl -s ifconfig.me)
DOMAIN_IP=$(dig +short "$DOMAIN" | head -n1)

if [ "$SERVER_IP" = "$DOMAIN_IP" ]; then
    log_info "Domain $DOMAIN correctly points to this server ($SERVER_IP)"
else
    log_warn "Domain $DOMAIN resolves to $DOMAIN_IP, but server IP is $SERVER_IP"
    log_warn "This may cause issues with Let's Encrypt"
fi

# Test HTTPS endpoint
sleep 2
if curl -k -s "https://localhost" > /dev/null 2>&1; then
    log_info "HTTPS endpoint is responding"
else
    log_warn "HTTPS endpoint is not responding yet (may need a moment to start)"
fi

##############################################################################
# Deployment Complete
##############################################################################

echo ""
echo "=========================================================================="
log_info "Deployment complete!"
echo "=========================================================================="
echo ""
echo "Services:"
echo "  - Honeypot:     systemctl status honeypot.service"
echo "  - Web UI:       systemctl status honeypot-web.service"
echo "  - nginx:        systemctl status nginx"
echo "  - fail2ban:     systemctl status fail2ban"
echo ""
echo "Access:"
echo "  - Web UI:       https://$DOMAIN"
echo "  - Credentials:  See $APP_DIR/.env"
echo ""
echo "Logs:"
echo "  - Honeypot:     journalctl -u honeypot.service -f"
echo "  - Web UI:       journalctl -u honeypot-web.service -f"
echo "  - nginx:        tail -f /var/log/nginx/honeypot_access.log"
echo "  - fail2ban:     fail2ban-client status honeypot-web"
echo ""
echo "Next steps:"
echo "  1. Review credentials in $APP_DIR/.env"
echo "  2. Test web UI at https://$DOMAIN"
echo "  3. Monitor logs for connections"
echo ""
echo "=========================================================================="
