require 'rake/testtask'

# Default task
task default: :test

# Run all tests
Rake::TestTask.new(:test) do |t|
  t.libs << 'test'
  t.libs << 'lib'
  t.test_files = FileList['test/**/test_*.rb']
  t.verbose = true
  t.warning = false
end

# Run only unit tests
Rake::TestTask.new(:test_unit) do |t|
  t.libs << 'test'
  t.libs << 'lib'
  t.test_files = FileList['test/unit/test_*.rb']
  t.verbose = true
  t.warning = false
end

# Run only integration tests
Rake::TestTask.new(:test_integration) do |t|
  t.libs << 'test'
  t.libs << 'lib'
  t.test_files = FileList['test/integration/test_*.rb']
  t.verbose = true
  t.warning = false
end

# Run tests with verbose output
Rake::TestTask.new(:test_verbose) do |t|
  t.libs << 'test'
  t.libs << 'lib'
  t.test_files = FileList['test/**/test_*.rb']
  t.verbose = true
  t.warning = true
end

desc "List all available test tasks"
task :test_tasks do
  puts "Available test tasks:"
  puts "  rake test              # Run all tests"
  puts "  rake test_unit         # Run unit tests only"
  puts "  rake test_integration  # Run integration tests only"
  puts "  rake test_verbose      # Run tests with verbose output"
end

##############################################################################
# Deployment Tasks (require root)
##############################################################################

namespace :deploy do
  DOMAIN = "honeypot.officemsoft.com"
  APP_DIR = "/opt/honeypot"
  HONEYPOT_USER = "honeypot"
  WEB_PORT = "4167"

  def check_root!
    unless Process.uid == 0
      abort "❌ This task must be run as root. Use: sudo rake #{ARGV.first}"
    end
  end

  def log_info(msg)
    puts "\e[32m[INFO]\e[0m #{msg}"
  end

  def log_warn(msg)
    puts "\e[33m[WARN]\e[0m #{msg}"
  end

  def log_error(msg)
    puts "\e[31m[ERROR]\e[0m #{msg}"
  end

  def run(cmd, description: nil)
    log_info description if description
    system(cmd) or abort "❌ Command failed: #{cmd}"
  end

  def run_quiet(cmd)
    system(cmd, out: File::NULL, err: File::NULL)
  end

  desc "Full deployment (first time or major updates)"
  task :full do
    check_root!

    log_info "Starting full deployment for #{DOMAIN}..."

    # Install system packages
    log_info "Installing system dependencies..."
    run "apt-get update -qq", description: "Updating package lists"

    packages = %w[ruby ruby-dev build-essential git nginx certbot python3-certbot-nginx fail2ban cron]
    packages.each do |pkg|
      if run_quiet("dpkg -l | grep -q '^ii  #{pkg} '")
        log_info "#{pkg} already installed"
      else
        run "apt-get install -y #{pkg}", description: "Installing #{pkg}"
      end
    end

    # Create honeypot user
    log_info "Creating honeypot system user..."
    if run_quiet("id #{HONEYPOT_USER}")
      log_info "User #{HONEYPOT_USER} already exists"
    else
      run "useradd --system --home-dir #{APP_DIR} --shell /usr/sbin/nologin --comment 'Honeypot Service User' #{HONEYPOT_USER}"
      log_info "Created user #{HONEYPOT_USER}"
    end

    # Install Ruby gems
    log_info "Installing Ruby gems system-wide..."
    %w[sinatra~>4.0 puma~>6.0 rackup~>2.0 json~>2.7].each do |gem|
      run_quiet "gem install #{gem.gsub('~>', ' -v ')} --conservative 2>&1"
    end
    log_info "Ruby gems installed"

    # Set ownership
    if Dir.exist?(APP_DIR)
      run "chown -R #{HONEYPOT_USER}:#{HONEYPOT_USER} #{APP_DIR}"

      # Add git safe directory
      if Dir.exist?("#{APP_DIR}/.git")
        run_quiet "git config --global --add safe.directory #{APP_DIR}"
      end

      # Create .env if needed
      env_file = "#{APP_DIR}/.env"
      unless File.exist?(env_file)
        log_info "Creating .env file..."
        if File.exist?("#{APP_DIR}/.env.example")
          run "cp #{APP_DIR}/.env.example #{env_file}"
        else
          File.write(env_file, <<~ENV)
            WEB_USERNAME=admin
            WEB_PASSWORD=change_me_#{SecureRandom.hex(8)}
          ENV
        end
        run "chown #{HONEYPOT_USER}:#{HONEYPOT_USER} #{env_file}"
        log_warn "Please edit #{env_file} and set WEB_USERNAME and WEB_PASSWORD"
      end

      # Create logs directory
      run "mkdir -p #{APP_DIR}/logs"
      run "chown -R #{HONEYPOT_USER}:#{HONEYPOT_USER} #{APP_DIR}/logs"
    else
      log_error "#{APP_DIR} does not exist. Please clone the repository there first."
      abort
    end

    # SSL certificate
    log_info "Setting up Let's Encrypt SSL..."
    cert_path = "/etc/letsencrypt/live/#{DOMAIN}/fullchain.pem"

    unless File.exist?(cert_path)
      log_info "Obtaining SSL certificate for #{DOMAIN}..."
      run_quiet "systemctl stop nginx"
      run "certbot certonly --standalone -d #{DOMAIN} --non-interactive --agree-tos --register-unsafely-without-email"
      log_info "SSL certificate obtained successfully"
    else
      log_info "SSL certificate already exists"
    end

    # Set up auto-renewal
    if system("command -v crontab &> /dev/null")
      unless system("crontab -l 2>/dev/null | grep -q 'certbot renew'")
        log_info "Setting up automatic SSL renewal..."
        cron_entry = "0 3 * * * certbot renew --quiet --post-hook 'systemctl reload nginx'"
        existing = `crontab -l 2>/dev/null`.strip
        new_crontab = existing.empty? ? cron_entry : "#{existing}\n#{cron_entry}"
        IO.popen("crontab -", "w") { |f| f.puts new_crontab }
      end
    else
      log_warn "cron not available (certbot will use systemd timer)"
    end

    # Configure nginx
    log_info "Configuring nginx..."
    nginx_config = "/etc/nginx/sites-available/honeypot"

    File.write(nginx_config, <<~NGINX)
      # Redirect HTTP to HTTPS
      server {
          listen 80;
          listen [::]:80;
          server_name #{DOMAIN};

          location /.well-known/acme-challenge/ {
              root /var/www/html;
          }

          location / {
              return 301 https://$host$request_uri;
          }
      }

      # HTTPS server
      server {
          listen 443 ssl;
          listen [::]:443 ssl;
          http2 on;
          server_name #{DOMAIN};

          # SSL certificates
          ssl_certificate /etc/letsencrypt/live/#{DOMAIN}/fullchain.pem;
          ssl_certificate_key /etc/letsencrypt/live/#{DOMAIN}/privkey.pem;

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
              proxy_pass http://127.0.0.1:#{WEB_PORT};
              proxy_set_header Host $host;
              proxy_set_header X-Real-IP $remote_addr;
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-Proto $scheme;

              # Pass through Authorization header for Basic Auth
              proxy_set_header Authorization $http_authorization;
              proxy_pass_header Authorization;

              # WebSocket support
              proxy_http_version 1.1;
              proxy_set_header Upgrade $http_upgrade;
              proxy_set_header Connection "upgrade";

              # Timeouts
              proxy_connect_timeout 60s;
              proxy_send_timeout 60s;
              proxy_read_timeout 60s;
          }
      }
    NGINX

    nginx_enabled = "/etc/nginx/sites-enabled/honeypot"
    unless File.symlink?(nginx_enabled)
      File.symlink(nginx_config, nginx_enabled)
      log_info "Enabled nginx site"
    end

    # Remove default site
    default_site = "/etc/nginx/sites-enabled/default"
    if File.exist?(default_site)
      File.unlink(default_site)
      log_info "Removed default nginx site"
    end

    # Test and start nginx
    abort "nginx configuration is invalid!" unless system("nginx -t")
    log_info "nginx configuration is valid"

    run_quiet "systemctl enable nginx"
    run_quiet "systemctl start nginx"
    run_quiet "systemctl reload nginx"
    log_info "nginx is running with SSL"

    # Create systemd services
    log_info "Creating systemd services..."

    File.write("/etc/systemd/system/honeypot.service", <<~SERVICE)
      [Unit]
      Description=Network Honeypot with Dynamic Port Rotation
      After=network.target

      [Service]
      Type=simple
      User=#{HONEYPOT_USER}
      WorkingDirectory=#{APP_DIR}
      ExecStart=/usr/bin/ruby #{APP_DIR}/honeypot.rb --preset nmap-top-200
      Restart=always
      RestartSec=10
      StandardOutput=journal
      StandardError=journal

      # Allow binding to privileged ports without root
      AmbientCapabilities=CAP_NET_BIND_SERVICE
      NoNewPrivileges=true

      # Security hardening
      PrivateTmp=true
      ProtectSystem=strict
      ProtectHome=true
      ReadWritePaths=#{APP_DIR}/logs /tmp

      [Install]
      WantedBy=multi-user.target
    SERVICE

    File.write("/etc/systemd/system/honeypot-web.service", <<~SERVICE)
      [Unit]
      Description=Honeypot Web UI
      After=network.target honeypot.service

      [Service]
      Type=simple
      User=#{HONEYPOT_USER}
      WorkingDirectory=#{APP_DIR}
      Environment="RACK_ENV=production"
      ExecStart=/usr/bin/ruby #{APP_DIR}/web_ui.rb
      Restart=always
      RestartSec=10
      StandardOutput=journal
      StandardError=journal

      # Security hardening
      PrivateTmp=true
      ProtectSystem=strict
      ProtectHome=true
      ReadWritePaths=#{APP_DIR}/logs /tmp

      [Install]
      WantedBy=multi-user.target
    SERVICE

    run "systemctl daemon-reload"
    run "systemctl enable honeypot.service honeypot-web.service"
    run "systemctl restart honeypot.service honeypot-web.service"

    sleep 1

    if run_quiet("systemctl is-active --quiet honeypot.service")
      log_info "honeypot.service is running"
    else
      log_error "honeypot.service failed to start!"
      system "systemctl status honeypot.service --no-pager"
      abort
    end

    if run_quiet("systemctl is-active --quiet honeypot-web.service")
      log_info "honeypot-web.service is running"
    else
      log_error "honeypot-web.service failed to start!"
      system "systemctl status honeypot-web.service --no-pager"
      abort
    end

    # Configure fail2ban
    log_info "Configuring fail2ban..."

    File.write("/etc/fail2ban/filter.d/honeypot-web.conf", <<~FILTER)
      [Definition]
      failregex = ^<HOST> - .* ".*" 401 .*
      ignoreregex =
    FILTER

    File.write("/etc/fail2ban/jail.d/honeypot-web.conf", <<~JAIL)
      [honeypot-web]
      enabled = true
      port = 443
      filter = honeypot-web
      logpath = /var/log/nginx/honeypot_access.log
      maxretry = 5
      findtime = 600
      bantime = 3600
      action = iptables-multiport[name=honeypot-web, port="80,443", protocol=tcp]
    JAIL

    run "systemctl enable fail2ban"
    run "systemctl restart fail2ban"
    log_info "fail2ban is configured"

    # Note: No firewall (ufw/iptables) - honeypot needs all ports open
    log_info "Skipping firewall configuration (honeypot requires all ports open)"

    # Done
    puts "\n" + "=" * 74
    log_info "Deployment complete!"
    puts "=" * 74
    puts "\nServices:"
    puts "  honeypot:  systemctl status honeypot.service"
    puts "  web UI:    systemctl status honeypot-web.service"
    puts "\nAccess:"
    puts "  Web UI:    https://#{DOMAIN}"
    puts "  Config:    #{APP_DIR}/.env"
    puts "\nLogs:"
    puts "  journalctl -u honeypot.service -f"
    puts "  journalctl -u honeypot-web.service -f"
    puts ""
  end

  desc "Quick update (pull code, update gems, restart services)"
  task :update do
    check_root!

    log_info "Updating honeypot application..."

    unless Dir.exist?(APP_DIR)
      log_error "#{APP_DIR} does not exist"
      abort
    end

    Dir.chdir(APP_DIR) do
      # Pull latest code
      if Dir.exist?(".git")
        log_info "Pulling latest code..."
        run_quiet "git config --global --add safe.directory #{APP_DIR}"
        run_quiet "git stash push -m 'Auto-stash before update' -- ':!.env'"
        run "git pull"
        run_quiet "git stash pop"
      else
        log_error "Not a git repository"
        abort
      end

      # Update gems
      log_info "Updating Ruby gems..."
      %w[sinatra~>4.0 puma~>6.0 rackup~>2.0 json~>2.7].each do |gem|
        run_quiet "gem install #{gem.gsub('~>', ' -v ')} --conservative 2>&1"
      end
      log_info "Ruby gems updated"

      # Fix ownership
      run "chown -R #{HONEYPOT_USER}:#{HONEYPOT_USER} #{APP_DIR}"

      # Restart services
      log_info "Restarting services..."
      run "systemctl restart honeypot.service honeypot-web.service"
      run "systemctl reload nginx"

      sleep 1

      if run_quiet("systemctl is-active --quiet honeypot.service")
        log_info "honeypot.service restarted successfully"
      else
        log_error "honeypot.service failed to start!"
        system "systemctl status honeypot.service --no-pager"
        abort
      end

      if run_quiet("systemctl is-active --quiet honeypot-web.service")
        log_info "honeypot-web.service restarted successfully"
      else
        log_error "honeypot-web.service failed to start!"
        system "systemctl status honeypot-web.service --no-pager"
        abort
      end

      if run_quiet("systemctl is-active --quiet nginx")
        log_info "nginx reloaded successfully"
      else
        log_warn "nginx is not running"
      end
    end

    puts "\n" + "=" * 74
    log_info "Update complete!"
    puts "=" * 74
    puts "\nServices status:"
    system "systemctl status honeypot.service --no-pager -l | head -5"
    puts ""
    system "systemctl status honeypot-web.service --no-pager -l | head -5"
    puts ""
  end

  desc "Show deployment status"
  task :status do
    puts "\n" + "=" * 74
    puts "Honeypot Deployment Status"
    puts "=" * 74
    puts "\nServices:"
    system "systemctl is-active honeypot.service &>/dev/null && echo '  ✓ honeypot.service: running' || echo '  ✗ honeypot.service: stopped'"
    system "systemctl is-active honeypot-web.service &>/dev/null && echo '  ✓ honeypot-web.service: running' || echo '  ✗ honeypot-web.service: stopped'"
    system "systemctl is-active nginx &>/dev/null && echo '  ✓ nginx: running' || echo '  ✗ nginx: stopped'"
    system "systemctl is-active fail2ban &>/dev/null && echo '  ✓ fail2ban: running' || echo '  ✗ fail2ban: stopped'"

    if File.exist?("/etc/letsencrypt/live/#{DOMAIN}/fullchain.pem")
      cert_info = `openssl x509 -in /etc/letsencrypt/live/#{DOMAIN}/fullchain.pem -noout -enddate 2>/dev/null`.strip
      puts "\nSSL Certificate:"
      puts "  ✓ #{cert_info.sub('notAfter=', 'Expires: ')}"
    end

    puts "\nAccess:"
    puts "  https://#{DOMAIN}"
    puts ""
  end
end

# Shortcuts for common tasks
desc "Deploy honeypot to production (alias for deploy:full)"
task :deploy => 'deploy:full'

desc "Update honeypot deployment (alias for deploy:update)"
task :update => 'deploy:update'
