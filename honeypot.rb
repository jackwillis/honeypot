#!/usr/bin/env ruby
require 'socket'
require 'logger'
require 'time'
require 'set'

class Honeypot
  # Nmap's most commonly scanned ports (top 200)
  NMAP_TOP_200 = [
    1, 3, 7, 9, 13, 17, 19, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 82, 88, 100,
    106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 254, 255, 280, 311, 389,
    427, 443, 444, 445, 464, 465, 497, 513, 514, 515, 543, 544, 548, 554, 587, 593,
    625, 631, 636, 646, 787, 808, 873, 902, 990, 993, 995, 999, 1000, 1022, 1024,
    1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1035, 1036, 1037, 1038,
    1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051,
    1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064,
    1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077,
    1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090,
    1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105,
    1106, 1107, 1108, 1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123,
    1124, 1126, 1130, 1131, 1132, 1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151,
    1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175, 1183, 1185, 1186, 1187,
    1192, 1198, 1199, 1201, 1213, 1216, 1217, 1233, 1234, 1236, 1244, 1247, 1248,
    1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328,
    1334, 1352
  ]

  # Nmap top 1000 (subset for reference - can expand if needed)
  NMAP_TOP_1000_EXTRA = (1..10000).select { |p| p % 10 == 0 } # Placeholder

  def initialize(options = {})
    # Determine port range based on preset or explicit range
    @port_range = if options[:preset]
      get_preset_ports(options[:preset])
    elsif options[:port_range]
      options[:port_range]
    else
      # Default to Nmap top 200 to avoid file descriptor issues
      NMAP_TOP_200
    end

    @bind_ip = options[:bind_ip] || '0.0.0.0'  # Listen on all interfaces
    @open_chance = options[:open_chance] || 70
    @filtered_chance = options[:filtered_chance] || 20
    @rotation_interval = options[:rotation_interval] || 10  # Rotate ports every N seconds

    @servers = {}
    @threads = []
    @running = true
    @well_known_ports = Set.new  # Track well-known ports for consistent behavior
    @rotation_mutex = Mutex.new  # Thread-safe port rotation
    @available_ports = []        # Ports available in range
    @currently_bound = Set.new   # Currently bound ports
    @currently_unbound = Set.new # Currently unbound ports

    setup_logging
    check_file_descriptor_limit
    setup_signal_handlers
    detect_network_config
  end

  def get_preset_ports(preset)
    case preset.to_s.downcase
    when 'nmap-top-200', 'nmap200', 'top200'
      NMAP_TOP_200
    when 'nmap-top-1000', 'nmap1000', 'top1000'
      NMAP_TOP_200 + NMAP_TOP_1000_EXTRA
    when 'all'
      (1..65535)
    when 'high'
      (1024..65535)
    when 'common'
      (1..1024)
    else
      @logger.warn "Unknown preset '#{preset}', using nmap-top-200"
      NMAP_TOP_200
    end
  end

  def check_file_descriptor_limit
    # Check if we're likely to hit file descriptor limits
    if @port_range.is_a?(Array)
      port_count = @port_range.size
    else
      port_count = @port_range.size
    end

    # Get current soft limit (Ruby doesn't have direct access, so we estimate)
    # Most systems: 1024 (default) or 4096
    # We'll check via ulimit if available
    begin
      current_limit = `ulimit -n 2>/dev/null`.strip.to_i
      current_limit = 1024 if current_limit == 0 # fallback
    rescue
      current_limit = 1024 # conservative estimate
    end

    # Warn if we're likely to exceed (leaving room for other FDs)
    safety_margin = 50
    if port_count > (current_limit - safety_margin)
      @logger.warn "=" * 70
      @logger.warn "WARNING: Attempting to bind #{port_count} ports"
      @logger.warn "Current file descriptor limit: #{current_limit}"
      @logger.warn "This may fail with 'Too many open files' errors!"
      @logger.warn ""
      @logger.warn "Solutions:"
      @logger.warn "  1. Increase limit: ulimit -n #{port_count + 100}"
      @logger.warn "  2. Use preset: ruby honeypot.rb --preset nmap-top-200"
      @logger.warn "  3. Reduce range: ruby honeypot.rb -r 8000:9000"
      @logger.warn "=" * 70

      # Give user a chance to cancel
      sleep(3)
    end
  end

  def start
    @logger.info "Starting Network-Aware Honeypot"
    @logger.info "Listening on: #{@bind_ip}"
    @logger.info "Network interfaces: #{@network_info}"

    # Display port configuration
    if @port_range.is_a?(Array)
      @logger.info "Ports: #{@port_range.size} ports (preset: Nmap top 200)"
    else
      @logger.info "Port range: #{@port_range.first}-#{@port_range.last} (#{@port_range.size} ports)"
    end
    @logger.info "Port binding: #{@open_chance}% open (bound), #{100 - @open_chance}% closed (unbound)"
    @logger.info "Port rotation: Every #{@rotation_interval} seconds"

    bind_initial_ports
    start_port_rotation_manager

    @logger.info "Honeypot ready! Scan me at: #{@scan_targets.join(', ')}"

    while @running
      sleep(1)
      cleanup_dead_threads
    end

    shutdown
  end

  private

  def detect_network_config
    @network_info = {}
    @scan_targets = []
    
    # Get all network interfaces
    Socket.getifaddrs.each do |ifaddr|
      next unless ifaddr.addr&.ipv4? && !ifaddr.addr.ipv4_loopback?
      
      ip = ifaddr.addr.ip_address
      @network_info[ifaddr.name] = ip
      @scan_targets << ip
    end
    
    @logger.info "Detected interfaces: #{@network_info}"
  end

  def bind_initial_ports
    # Define well-known service ports that should always be bound
    well_known_port_list = [
      21,   # FTP
      22,   # SSH
      23,   # Telnet
      25,   # SMTP
      53,   # DNS
      80,   # HTTP
      110,  # POP3
      143,  # IMAP
      443,  # HTTPS
      465,  # SMTPS
      587,  # SMTP Submission
      993,  # IMAPS
      995,  # POP3S
      3306, # MySQL
      3389, # RDP
      5432, # PostgreSQL
      5900, # VNC
      6379, # Redis
      8000, # HTTP Alt
      8080, # HTTP Proxy
      8443, # HTTPS Alt
      27017 # MongoDB
    ]

    # Store well-known ports in instance variable
    @well_known_ports = Set.new(well_known_port_list)

    # Build available ports list (excluding privileged if not root)
    @port_range.each do |port|
      next if port < 1024 && Process.uid != 0
      @available_ports << port
    end

    # Calculate how many ports to bind initially
    target_open_count = (@available_ports.size * @open_chance / 100.0).round

    # Separate well-known from others
    well_known_in_range = @available_ports & @well_known_ports.to_a
    other_ports = @available_ports - well_known_in_range

    # Always bind well-known ports first
    ports_to_bind = well_known_in_range.dup

    # Add random selection of other ports to meet target
    remaining_needed = target_open_count - ports_to_bind.size
    if remaining_needed > 0
      ports_to_bind += other_ports.sample(remaining_needed)
    end

    # Bind selected ports
    bound_count = 0
    ports_to_bind.each do |port|
      if bind_port(port)
        bound_count += 1
        @currently_bound.add(port)
        if @well_known_ports.include?(port)
          @logger.info "Bound well-known service port: #{port} (#{service_name(port)})"
        end
      end
    end

    # Track unbound ports
    @currently_unbound = Set.new(@available_ports - @currently_bound.to_a)

    rotatable_count = bound_count - well_known_in_range.size
    @logger.info "Initially bound #{bound_count}/#{@available_ports.size} ports (#{(@open_chance)}% target)"
    @logger.info "Well-known ports (always bound): #{well_known_in_range.size}, Rotatable ports: #{rotatable_count}"
    @logger.info "Expected rotation: ~30-50 ports every #{@rotation_interval}s (30-50% of rotatable ports, min 30)"
  end

  def bind_port(port)
    @rotation_mutex.synchronize do
      begin
        server = TCPServer.new(@bind_ip, port)
        server.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)

        # Start listener thread for this port
        thread = Thread.new do
          handle_port(port, server, :open)
        end

        @servers[port] = { server: server, type: :open, thread: thread }
        @threads << thread
        @logger.debug "[BIND] Port #{port} bound and listening"
        true
      rescue Errno::EADDRINUSE => e
        @logger.warn "[BIND] Port #{port} already in use"
        false
      rescue Errno::EACCES => e
        @logger.warn "[BIND] Port #{port} permission denied"
        false
      rescue => e
        @logger.error "[BIND] Port #{port} error: #{e.message}"
        false
      end
    end
  end

  def unbind_port(port)
    @rotation_mutex.synchronize do
      return false unless @servers[port]

      begin
        config = @servers[port]

        # Close the server socket
        config[:server].close rescue nil

        # The thread will exit when the server closes
        # We'll let cleanup_dead_threads handle it

        @servers.delete(port)
        @logger.debug "[UNBIND] Port #{port}"
        true
      rescue => e
        @logger.error "[UNBIND] Port #{port} error: #{e.message}"
        false
      end
    end
  end

  def start_port_rotation_manager
    @logger.info "[ROTATION] Starting port rotation manager (interval: #{@rotation_interval}s)"

    @rotation_thread = Thread.new do
      while @running
        sleep(@rotation_interval)

        begin
          rotate_ports
        rescue => e
          @logger.error "[ROTATION] Error during rotation: #{e.message}"
          @logger.debug e.backtrace.join("\n")
        end
      end
    end

    @threads << @rotation_thread
  end

  def rotate_ports
    # Don't rotate well-known ports (they stay bound)
    rotatable_bound = @currently_bound.to_a - @well_known_ports.to_a
    rotatable_unbound = @currently_unbound.to_a - @well_known_ports.to_a

    return if rotatable_bound.empty? || rotatable_unbound.empty?

    # Rotate 30-50% of rotatable ports each cycle (more aggressive for better ephemeral behavior)
    rotation_percentage = rand(30..50)
    num_to_rotate = (rotatable_bound.size * rotation_percentage / 100.0).round

    # Ensure we rotate at least 30 ports (or all available if less)
    # This guarantees substantial port changes for Nmap top 200
    minimum_rotation = 30
    num_to_rotate = [num_to_rotate, minimum_rotation].max

    # Don't try to rotate more than available
    num_to_rotate = [num_to_rotate, rotatable_bound.size, rotatable_unbound.size].min

    # Select random ports to unbind and bind
    ports_to_unbind = rotatable_bound.sample(num_to_rotate)
    ports_to_bind = rotatable_unbound.sample(num_to_rotate)

    unbind_count = 0
    bind_count = 0

    # Unbind selected ports
    ports_to_unbind.each do |port|
      if unbind_port(port)
        @currently_bound.delete(port)
        @currently_unbound.add(port)
        unbind_count += 1
      end
    end

    # Bind new ports
    ports_to_bind.each do |port|
      if bind_port(port)
        @currently_unbound.delete(port)
        @currently_bound.add(port)
        bind_count += 1
      end
    end

    # Calculate what percentage of non-well-known ports changed
    if rotatable_bound.size > 0
      rotation_percent = (unbind_count.to_f / rotatable_bound.size * 100).round
      @logger.info "[ROTATION] Cycled #{unbind_count} closed, #{bind_count} opened (#{rotation_percent}% of rotatable). Total: #{@currently_bound.size} bound, #{@currently_unbound.size} unbound"
    else
      @logger.info "[ROTATION] Cycled #{unbind_count} closed, #{bind_count} opened. Total: #{@currently_bound.size} bound, #{@currently_unbound.size} unbound"
    end
  end

  def handle_port(port, server, type)
    while @running
      begin
        ready = IO.select([server], nil, nil, 1)
        next unless ready

        client = server.accept_nonblock
        peer = client.peeraddr
        peer_ip = peer[3]
        peer_port = peer[1]

        @logger.info "[ACCEPT] Connection from #{peer_ip}:#{peer_port} to port #{port}"

        # Port is bound, so it's open at the TCP level
        # Now decide if we respond (open) or hang (filtered)
        # Well-known ports always respond; others are random
        if @well_known_ports.include?(port)
          @logger.info "[OPEN] #{peer_ip}:#{peer_port} -> #{port} - Well-known service"
          handle_open_connection(client, port, peer_ip, peer_port)
        elsif rand(100) < @filtered_chance
          # Simulate filtered: accept but don't respond
          @logger.info "[FILTERED] #{peer_ip}:#{peer_port} -> #{port} - Simulating filtered port"
          handle_filtered_connection(client, port, peer_ip, peer_port)
        else
          # Normal open response
          @logger.info "[OPEN] #{peer_ip}:#{peer_port} -> #{port} - Responding"
          handle_open_connection(client, port, peer_ip, peer_port)
        end

      rescue IO::WaitReadable
        next
      rescue Errno::EBADF, IOError
        # Server socket was closed (rotation), exit gracefully
        break
      rescue => e
        @logger.error "[ERROR] Port #{port} error: #{e.message}"
        @logger.debug e.backtrace.join("\n")
        break
      end
    end
  end

  def handle_open_connection(client, port, peer_ip, peer_port)
    Thread.new do
      start_time = Time.now
      begin
        # Set socket options for more realistic behavior
        client.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)

        # Send banner immediately for services that do so
        if should_send_banner_immediately?(port)
          banner = generate_banner(port)
          if banner
            @logger.debug "[SEND] #{peer_ip}:#{peer_port} -> #{port} - Banner (#{banner.bytesize} bytes)"
            client.write(banner)
            client.flush
          end
        end

        # Handle interactive protocols
        handle_protocol_interaction(client, port)

      rescue Errno::ECONNRESET, Errno::EPIPE => e
        @logger.debug "[RESET] #{peer_ip}:#{peer_port} -> #{port} - Connection reset by peer"
      rescue => e
        @logger.error "[ERROR] #{peer_ip}:#{peer_port} -> #{port} - #{e.message}"
        @logger.debug e.backtrace.join("\n")
      ensure
        duration = Time.now - start_time
        @logger.info "[CLOSE] #{peer_ip}:#{peer_port} -> #{port} (#{duration.round(2)}s)"
        client.close rescue nil
      end
    end
  end

  def handle_filtered_connection(client, port, peer_ip, peer_port)
    Thread.new do
      start_time = Time.now
      begin
        # Filtered ports accept the connection but don't respond
        # This simulates a firewall dropping packets or a timeout
        # Sleep briefly to simulate network delay/timeout
        timeout = rand(2..5)
        @logger.debug "[FILTERED] #{peer_ip}:#{peer_port} -> #{port} - Holding for #{timeout}s"
        sleep(timeout)
      rescue => e
        @logger.error "[ERROR] #{peer_ip}:#{peer_port} -> #{port} - #{e.message}"
        @logger.debug e.backtrace.join("\n")
      ensure
        duration = Time.now - start_time
        @logger.info "[CLOSE] #{peer_ip}:#{peer_port} -> #{port} (#{duration.round(2)}s) [filtered]"
        client.close rescue nil
      end
    end
  end

  def handle_closed_connection(client, port, peer_ip, peer_port)
    Thread.new do
      begin
        # Closed ports immediately disconnect (RST)
        # Just close immediately without any response
      rescue => e
        @logger.error "[ERROR] #{peer_ip}:#{peer_port} -> #{port} - #{e.message}"
        @logger.debug e.backtrace.join("\n")
      ensure
        @logger.debug "[CLOSE] #{peer_ip}:#{peer_port} -> #{port} [immediate RST]"
        client.close rescue nil
      end
    end
  end

  def should_send_banner_immediately?(port)
    # These services send banners immediately upon connection
    [21, 22, 23, 25, 110, 143, 220, 465, 587, 990, 119, 3306, 5432, 6379].include?(port)
  end

  def handle_protocol_interaction(client, port)
    case port
    when 80, 8000, 8080, 8081, 8888, 8443
      handle_http(client, port)
    when 22
      handle_ssh(client, port)
    when 21
      handle_ftp(client, port)
    when 25, 465, 587
      handle_smtp(client, port)
    when 3306
      handle_mysql(client, port)
    when 5432
      handle_postgres(client, port)
    when 6379
      handle_redis(client, port)
    when 23
      handle_telnet(client, port)
    when 110
      handle_pop3(client, port)
    when 143
      handle_imap(client, port)
    when 443
      handle_https(client, port)
    when 3389
      handle_rdp(client, port)
    when 5900
      handle_vnc(client, port)
    when 27017
      handle_mongodb(client, port)
    when 53
      handle_dns_tcp(client, port)
    when 993, 995
      handle_tls_service(client, port)
    else
      # For unknown ports, randomly pick a simple service to emulate
      handle_random_service(client, port)
    end
  end

  def handle_http(client, port)
    begin
      # Wait for HTTP request
      request = client.gets
      return unless request

      @logger.debug "[HTTP] Port #{port} - #{request.strip}"

      # Send proper HTTP response
      response = "HTTP/1.1 200 OK\r\n"
      response << "Server: nginx/1.18.0\r\n"
      response << "Date: #{Time.now.httpdate}\r\n"
      response << "Content-Type: text/html\r\n"
      response << "Content-Length: 91\r\n"
      response << "Connection: close\r\n"
      response << "\r\n"
      response << "<html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>\r\n"

      client.write(response)
      client.flush
    rescue Errno::ENOTCONN, Errno::EPIPE, Errno::ECONNRESET => e
      # Client disconnected, ignore
    rescue => e
      @logger.error "[HTTP] Port #{port} error: #{e.message}"
      @logger.debug e.backtrace.join("\n")
    end
  end

  def handle_ssh(client, port)
    # SSH banner already sent, wait for client response
    begin
      data = client.read_nonblock(255)
      @logger.debug "[SSH] Port #{port} - Received #{data.bytesize} bytes"

      # Send SSH protocol negotiation failure
      response = "\x00\x00\x00\x0c\x0a\x0e"
      client.write(response)
    rescue IO::WaitReadable
      # Client didn't send anything, that's fine
    rescue Errno::ENOTCONN, Errno::EPIPE, Errno::ECONNRESET => e
      # Client disconnected, ignore
    rescue => e
      @logger.error "[SSH] Port #{port} error: #{e.message}"
      @logger.debug e.backtrace.join("\n")
    end
  end

  def handle_ftp(client, port)
    begin
      loop do
        data = client.gets
        break unless data
        
        cmd = data.strip.upcase
        @logger.debug "FTP command on port #{port}: #{cmd}"
        
        case cmd
        when /^USER/
          client.write("331 User name okay, need password.\r\n")
        when /^PASS/
          client.write("530 Login incorrect.\r\n")
          break
        when /^QUIT/
          client.write("221 Goodbye.\r\n")
          break
        else
          client.write("500 Command not recognized.\r\n")
        end
        client.flush
      end
    rescue => e
      @logger.debug "FTP error: #{e.message}"
    end
  end

  def handle_smtp(client, port)
    begin
      loop do
        data = client.gets
        break unless data
        
        cmd = data.strip.upcase
        @logger.debug "SMTP command on port #{port}: #{cmd}"
        
        case cmd
        when /^HELO/, /^EHLO/
          client.write("250 Hello\r\n")
        when /^MAIL FROM/
          client.write("250 OK\r\n")
        when /^RCPT TO/
          client.write("250 OK\r\n")
        when /^DATA/
          client.write("354 End data with <CR><LF>.<CR><LF>\r\n")
        when /^QUIT/
          client.write("221 Bye\r\n")
          break
        else
          client.write("500 Command not recognized\r\n")
        end
        client.flush
      end
    rescue => e
      @logger.debug "SMTP error: #{e.message}"
    end
  end

  def handle_mysql(client, port)
    # MySQL handshake packet (simplified)
    handshake = [
      0x0a,                    # Protocol version
      "5.7.42\x00".bytes,      # Server version
      rand(1..9999),           # Thread ID (4 bytes)
      Array.new(8) { rand(256) }, # Auth plugin data part 1
      0x00,                    # Filler
      0xff, 0xf7,              # Capability flags
      0x21,                    # Character set
      0x00, 0x00,              # Status flags
      Array.new(13, 0x00)      # Reserved
    ].flatten
    
    packet_length = handshake.length
    header = [packet_length & 0xff, (packet_length >> 8) & 0xff, (packet_length >> 16) & 0xff, 0x00]
    
    begin
      client.write((header + handshake).pack('C*'))
      client.flush
      
      # Wait for client auth packet
      client.read_nonblock(1024)
      # Send auth failure
      error = [0xff, 0x15, 0x04].pack('C*') + "#28000Access denied\x00"
      client.write([error.length, 0, 0, 2].pack('C*') + error)
      client.flush
    rescue => e
      @logger.debug "MySQL error: #{e.message}"
    end
  end

  def handle_postgres(client, port)
    # Wait for startup message
    begin
      startup = client.read_nonblock(1024)
      # Send auth required
      client.write(['R', 5, 3].pack('aNn'))
      client.flush
    rescue => e
      @logger.debug "PostgreSQL error: #{e.message}"
    end
  end

  def handle_redis(client, port)
    begin
      loop do
        data = client.gets
        break unless data
        
        @logger.debug "Redis command on port #{port}: #{data.strip}"
        
        if data.start_with?('*')
          # Redis protocol
          parts = []
          count = data[1..-1].to_i
          count.times { client.gets; parts << client.gets }
          
          cmd = parts.first.to_s.strip.upcase
          case cmd
          when 'PING'
            client.write("+PONG\r\n")
          when 'INFO'
            client.write("$25\r\nredis_version:6.2.14\r\n\r\n")
          when 'QUIT'
            client.write("+OK\r\n")
            break
          else
            client.write("-ERR unknown command\r\n")
          end
        else
          client.write("-ERR Protocol error\r\n")
        end
        client.flush
      end
    rescue => e
      @logger.debug "Redis error: #{e.message}"
    end
  end

  def handle_telnet(client, port)
    begin
      # Telnet login prompt already sent
      username = client.gets
      if username
        client.write("Password: ")
        client.flush
        password = client.gets
        if password
          sleep(1)
          client.write("\r\nLogin incorrect\r\n")
          client.flush
        end
      end
    rescue => e
      @logger.debug "Telnet error: #{e.message}"
    end
  end

  def handle_pop3(client, port)
    begin
      loop do
        data = client.gets
        break unless data
        
        cmd = data.strip.upcase
        @logger.debug "POP3 command on port #{port}: #{cmd}"
        
        case cmd
        when /^USER/
          client.write("+OK User accepted\r\n")
        when /^PASS/
          client.write("-ERR Authentication failed\r\n")
          break
        when /^QUIT/
          client.write("+OK Bye\r\n")
          break
        else
          client.write("-ERR Unknown command\r\n")
        end
        client.flush
      end
    rescue => e
      @logger.debug "POP3 error: #{e.message}"
    end
  end

  def handle_imap(client, port)
    begin
      tag_num = 1
      loop do
        data = client.gets
        break unless data
        
        parts = data.strip.split(' ', 2)
        tag = parts[0]
        cmd = parts[1].to_s.upcase
        
        @logger.debug "IMAP command on port #{port}: #{cmd}"
        
        case cmd
        when 'CAPABILITY'
          client.write("* CAPABILITY IMAP4rev1 LOGIN\r\n")
          client.write("#{tag} OK CAPABILITY completed\r\n")
        when 'LOGIN'
          client.write("#{tag} NO LOGIN failed\r\n")
        when 'LOGOUT'
          client.write("* BYE IMAP4rev1 Server logging out\r\n")
          client.write("#{tag} OK LOGOUT completed\r\n")
          break
        else
          client.write("#{tag} BAD Unknown command\r\n")
        end
        client.flush
      end
    rescue => e
      @logger.debug "IMAP error: #{e.message}"
    end
  end

  def handle_generic(client, port)
    begin
      # Wait for any data
      data = client.read_nonblock(1024)
      @logger.debug "Generic data on port #{port}: #{data.inspect}"
      
      # Send a generic response
      responses = [
        "OK\r\n",
        "200 OK\r\n",
        "+OK\r\n",
        "220 Service ready\r\n"
      ]
      client.write(responses.sample)
      client.flush
    rescue IO::WaitReadable
      # No data sent
    rescue => e
      @logger.debug "Generic handler error: #{e.message}"
    end
  end

  def handle_random_service(client, port)
    # Randomly select a service type for non-standard ports
    services = [:http, :echo, :daytime, :simple_smtp, :simple_ftp, :simple_pop, :json_api]
    service = services.sample
    
    @logger.debug "Port #{port} emulating: #{service}"
    
    case service
    when :http
      handle_simple_http(client, port)
    when :echo
      handle_echo(client, port)
    when :daytime
      handle_daytime(client, port)
    when :simple_smtp
      handle_simple_smtp(client, port)
    when :simple_ftp
      handle_simple_ftp(client, port)
    when :simple_pop
      handle_simple_pop(client, port)
    when :json_api
      handle_json_api(client, port)
    end
  end

  def handle_simple_http(client, port)
    begin
      request = client.gets
      return unless request
      
      servers = ["nginx/1.18.0", "Apache/2.4.41", "Microsoft-IIS/10.0", "lighttpd/1.4.55"]
      response = "HTTP/1.1 200 OK\r\n"
      response << "Server: #{servers.sample}\r\n"
      response << "Date: #{Time.now.httpdate}\r\n"
      response << "Content-Type: text/html\r\n"
      response << "Content-Length: 44\r\n"
      response << "Connection: close\r\n"
      response << "\r\n"
      response << "<html><body>Service on port #{port}</body></html>"
      
      client.write(response)
      client.flush
    rescue => e
      @logger.debug "Simple HTTP error: #{e.message}"
    end
  end

  def handle_echo(client, port)
    begin
      # Echo service - returns whatever is sent
      data = client.read_nonblock(1024)
      client.write(data)
      client.flush
    rescue IO::WaitReadable
    rescue => e
      @logger.debug "Echo error: #{e.message}"
    end
  end

  def handle_daytime(client, port)
    # Daytime service - returns current time
    begin
      client.write("#{Time.now.strftime('%A, %B %d, %Y %H:%M:%S-%Z')}\r\n")
      client.flush
    rescue => e
      @logger.debug "Daytime error: #{e.message}"
    end
  end

  def handle_simple_smtp(client, port)
    begin
      client.write("220 mail-#{port}.example.com ESMTP Service Ready\r\n")
      client.flush
      
      data = client.gets
      if data && data.upcase.start_with?('EHLO', 'HELO')
        client.write("250 Hello\r\n")
        client.flush
      end
    rescue => e
      @logger.debug "Simple SMTP error: #{e.message}"
    end
  end

  def handle_simple_ftp(client, port)
    begin
      client.write("220 FTP Server (Port #{port}) ready.\r\n")
      client.flush
      
      data = client.gets
      if data
        cmd = data.strip.upcase
        if cmd.start_with?('USER')
          client.write("331 Password required\r\n")
        elsif cmd.start_with?('PASS')
          client.write("530 Login incorrect\r\n")
        else
          client.write("500 Unknown command\r\n")
        end
        client.flush
      end
    rescue => e
      @logger.debug "Simple FTP error: #{e.message}"
    end
  end

  def handle_simple_pop(client, port)
    begin
      client.write("+OK POP3 server ready on port #{port}\r\n")
      client.flush
      
      data = client.gets
      if data
        cmd = data.strip.upcase
        if cmd.start_with?('USER')
          client.write("+OK User accepted\r\n")
        elsif cmd.start_with?('PASS')
          client.write("-ERR Authentication failed\r\n")
        else
          client.write("-ERR Unknown command\r\n")
        end
        client.flush
      end
    rescue => e
      @logger.debug "Simple POP error: #{e.message}"
    end
  end

  def handle_json_api(client, port)
    begin
      request = client.gets
      return unless request
      
      response = "HTTP/1.1 200 OK\r\n"
      response << "Server: api-server/1.0\r\n"
      response << "Date: #{Time.now.httpdate}\r\n"
      response << "Content-Type: application/json\r\n"
      json = "{\"status\":\"ok\",\"port\":#{port},\"timestamp\":\"#{Time.now.iso8601}\"}"
      response << "Content-Length: #{json.length}\r\n"
      response << "Connection: close\r\n"
      response << "\r\n"
      response << json
      
      client.write(response)
      client.flush
    rescue => e
      @logger.debug "JSON API error: #{e.message}"
    end
  end

  def handle_https(client, port)
    # HTTPS requires TLS handshake - send TLS alert
    begin
      # TLS alert protocol - handshake failure
      client.write("\x15\x03\x01\x00\x02\x02\x28")
      client.flush
    rescue => e
      @logger.debug "HTTPS error: #{e.message}"
    end
  end

  def handle_rdp(client, port)
    # RDP initial connection
    begin
      # RDP negotiation failure response
      client.write("\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00")
      client.flush
    rescue => e
      @logger.debug "RDP error: #{e.message}"
    end
  end

  def handle_vnc(client, port)
    # VNC protocol version
    begin
      client.write("RFB 003.008\n")
      client.flush
    rescue => e
      @logger.debug "VNC error: #{e.message}"
    end
  end

  def handle_mongodb(client, port)
    # MongoDB wire protocol response
    begin
      # Send a simple error response
      error_doc = "\x00\x00\x00\x00" # Empty response
      client.write(error_doc)
      client.flush
    rescue => e
      @logger.debug "MongoDB error: #{e.message}"
    end
  end

  def handle_dns_tcp(client, port)
    # DNS over TCP
    begin
      # Read the query length (2 bytes) and query
      data = client.read_nonblock(1024)
      # Send back a simple REFUSED response
      if data && data.length > 2
        # Extract transaction ID from query
        tx_id = data[2..3]
        # DNS response with REFUSED
        response = tx_id + "\x81\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        length = [response.length].pack('n')
        client.write(length + response)
        client.flush
      end
    rescue IO::WaitReadable
    rescue => e
      @logger.debug "DNS TCP error: #{e.message}"
    end
  end

  def handle_tls_service(client, port)
    # Generic TLS service - send TLS alert
    begin
      # TLS alert - handshake failure
      client.write("\x15\x03\x03\x00\x02\x02\x28")
      client.flush
    rescue => e
      @logger.debug "TLS service error: #{e.message}"
    end
  end

  def service_name(port)
    names = {
      21 => 'FTP', 22 => 'SSH', 23 => 'Telnet', 25 => 'SMTP',
      53 => 'DNS', 80 => 'HTTP', 110 => 'POP3', 143 => 'IMAP',
      443 => 'HTTPS', 465 => 'SMTPS', 587 => 'SMTP-Submission',
      993 => 'IMAPS', 995 => 'POP3S', 3306 => 'MySQL',
      3389 => 'RDP', 5432 => 'PostgreSQL', 5900 => 'VNC',
      6379 => 'Redis', 8000 => 'HTTP-Alt', 8080 => 'HTTP-Proxy',
      8443 => 'HTTPS-Alt', 27017 => 'MongoDB'
    }
    names[port] || 'Unknown'
  end

  def generate_banner(port)
    case port
    when 22
      "SSH-2.0-OpenSSH_8.#{rand(4..9)}p1 Ubuntu-0ubuntu0.22.04.1\r\n"
    when 21
      "220 (vsFTPd 3.0.5)\r\n"
    when 23
      "\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27\r\nDebian GNU/Linux 11\r\n\r\nLogin: "
    when 25
      "220 mail.example.com ESMTP Postfix (Ubuntu)\r\n"
    when 465, 587
      "220 smtp.gmail.com ESMTP Exim 4.94.2 Ubuntu\r\n"
    when 110
      "+OK Dovecot (Ubuntu) ready.\r\n"
    when 143
      "* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE STARTTLS] Dovecot (Ubuntu) ready.\r\n"
    when 119
      "200 InterNetNews NNRP server INN 2.6.3 ready\r\n"
    when 3306
      nil # MySQL uses binary protocol
    when 5432
      nil # PostgreSQL uses binary protocol  
    when 6379
      nil # Redis waits for commands
    when 53
      nil # DNS doesn't banner
    when 443, 993, 995, 990
      nil # SSL/TLS ports need handshake
    else
      nil
    end
  end

  def setup_logging
    @logger = Logger.new($stdout)
    @logger.level = Logger::INFO
    @logger.formatter = proc do |severity, datetime, progname, msg|
      "[#{datetime.strftime('%H:%M:%S')}] #{severity}: #{msg}\n"
    end
  end

  def setup_signal_handlers
    Signal.trap('INT') { shutdown }
    Signal.trap('TERM') { shutdown }
  end

  def cleanup_dead_threads
    @threads.reject! { |t| !t.alive? }
  end

  def shutdown
    @logger.info "Shutting down..."
    @running = false
    @servers.each { |_, config| config[:server].close rescue nil }
    @threads.each { |t| t.join(1) }
    exit(0)
  end
end

# Parse command line options
require 'optparse'

options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: #{$0} [options]"
  opts.separator ""
  opts.separator "Port Selection Options:"

  opts.on("-p", "--preset PRESET", "Port preset (nmap-top-200, nmap-top-1000, all, high, common)") do |preset|
    options[:preset] = preset
  end

  opts.on("-r", "--range START:END", "Port range (e.g., 8000:9000)") do |range|
    start_port, end_port = range.split(':').map(&:to_i)
    options[:port_range] = (start_port..end_port)
  end

  opts.separator ""
  opts.separator "Network Options:"

  opts.on("-i", "--ip IP", "Bind IP (default: 0.0.0.0)") do |ip|
    options[:bind_ip] = ip
  end

  opts.separator ""
  opts.separator "Behavior Options:"

  opts.on("-o", "--open PERCENT", Integer, "Percentage of ports to bind (default: 70)") do |percent|
    options[:open_chance] = percent
  end

  opts.on("-f", "--filtered PERCENT", Integer, "Percentage of bound ports that hang (default: 20)") do |percent|
    options[:filtered_chance] = percent
  end

  opts.on("-t", "--rotation SECONDS", Integer, "Port rotation interval in seconds (default: 10)") do |seconds|
    options[:rotation_interval] = seconds
  end

  opts.separator ""
  opts.separator "Other Options:"

  opts.on("-h", "--help", "Show this help message") do
    puts opts
    puts ""
    puts "Examples:"
    puts "  #{$0}                                    # Default: Nmap top 200 ports"
    puts "  #{$0} --preset nmap-top-200             # Explicitly use Nmap top 200"
    puts "  #{$0} -r 8000:9000                      # Scan ports 8000-9000"
    puts "  #{$0} -o 80 -f 10 -t 5                  # 80% bound, 10% filtered, rotate every 5s"
    puts "  #{$0} --preset all -o 90 -t 30          # All ports, 90% bound, rotate every 30s"
    puts ""
    puts "How it works:"
    puts "  - Port states are TRULY ephemeral via dynamic rotation"
    puts "  - Bound ports: Respond to Nmap as 'open' or 'filtered'"
    puts "  - Unbound ports: OS sends RST (Nmap sees as 'closed')"
    puts "  - Every rotation interval, random ports are bound/unbound"
    puts "  - Well-known ports (SSH, HTTP, etc.) stay bound and always respond"
    puts ""
    puts "Default behavior:"
    puts "  - Ports: Nmap top 200 (prevents 'too many open files' errors)"
    puts "  - Binding: 70% of ports bound (open/filtered), 30% unbound (closed)"
    puts "  - Filtered: 20% of connections to bound ports hang (no response)"
    puts "  - Rotation: Ports change state every 10 seconds"
    exit
  end
end.parse!

# Run as non-root if possible (skips ports < 1024)
if Process.uid == 0
  puts "Running as root - can bind to all ports"
else
  puts "Running as user - will skip privileged ports (< 1024)"
end

honeypot = Honeypot.new(options)
honeypot.start

