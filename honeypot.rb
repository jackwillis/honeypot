#!/usr/bin/env ruby
require 'socket'
require 'logger'
require 'time'
require 'set'

class Honeypot
  def initialize(options = {})
    @port_range = options[:port_range] || (1..10000)
    @bind_ip = options[:bind_ip] || '0.0.0.0'  # Listen on all interfaces
    @open_chance = options[:open_chance] || 70
    @filtered_chance = options[:filtered_chance] || 20

    @servers = {}
    @threads = []
    @running = true
    @well_known_ports = Set.new  # Track well-known ports for consistent behavior

    setup_logging
    setup_signal_handlers
    detect_network_config
  end

  def start
    @logger.info "Starting Network-Aware Honeypot"
    @logger.info "Listening on: #{@bind_ip}"
    @logger.info "Network interfaces: #{@network_info}"
    @logger.info "Port range: #{@port_range}"
    
    bind_random_ports
    start_listeners
    
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

  def bind_random_ports
    available_ports = 0

    # Define well-known service ports that should always respond as open
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

    # Store well-known ports in instance variable for runtime checks
    @well_known_ports = Set.new(well_known_port_list)

    @port_range.each do |port|
      # Skip privileged ports if not root
      next if port < 1024 && Process.uid != 0

      # Bind ALL ports in range (state will be determined at connection time)
      if bind_open_port(port)
        available_ports += 1
        if @well_known_ports.include?(port)
          @logger.info "Bound well-known service port: #{port} (#{service_name(port)})"
        end
      end
    end

    @logger.info "Successfully bound #{available_ports} ports (state determined at runtime)"
  end

  def bind_open_port(port)
    begin
      server = TCPServer.new(@bind_ip, port)
      server.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
      @servers[port] = { server: server, type: :open }
      @logger.debug "Port #{port}: OPEN"
      true
    rescue Errno::EADDRINUSE => e
      @logger.debug "Port #{port}: already in use"
      false
    rescue Errno::EACCES => e
      @logger.debug "Port #{port}: permission denied"
      false
    rescue => e
      @logger.debug "Port #{port}: #{e.message}"
      false
    end
  end

  def determine_runtime_behavior(port)
    # Well-known ports always respond as open for realism
    return :open if @well_known_ports.include?(port)

    # For other ports, randomly choose behavior at connection time
    roll = rand(100)
    if roll < @open_chance
      :open
    elsif roll < @open_chance + @filtered_chance
      :filtered
    else
      :closed
    end
  end

  def start_listeners
    @servers.each do |port, config|
      @threads << Thread.new do
        handle_port(port, config[:server], config[:type])
      end
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

        # Determine behavior at runtime (truly ephemeral)
        behavior = determine_runtime_behavior(port)
        @logger.info "[STATE] Port #{port} decided: #{behavior.to_s.upcase}"

        case behavior
        when :open
          @logger.info "[OPEN] #{peer_ip}:#{peer_port} -> #{port} - Handling as OPEN"
          handle_open_connection(client, port, peer_ip, peer_port)
        when :filtered
          @logger.info "[FILTERED] #{peer_ip}:#{peer_port} -> #{port} - Simulating filtered port"
          handle_filtered_connection(client, port, peer_ip, peer_port)
        when :closed
          @logger.info "[CLOSED] #{peer_ip}:#{peer_port} -> #{port} - Closing immediately"
          handle_closed_connection(client, port, peer_ip, peer_port)
        end

      rescue IO::WaitReadable
        next
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
        @logger.info "[OPEN] #{peer_ip}:#{peer_port} -> #{port} - Connection established"

        # Set socket options for more realistic behavior
        client.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
        @logger.debug "[OPEN] #{peer_ip}:#{peer_port} -> #{port} - Socket options configured"

        # Send banner immediately for services that do so
        if should_send_banner_immediately?(port)
          banner = generate_banner(port)
          if banner
            @logger.info "[SEND] #{peer_ip}:#{peer_port} -> #{port} - Sending banner (#{banner.bytesize} bytes)"
            @logger.debug "[BANNER] #{banner.inspect}"
            client.write(banner)
            client.flush
          end
        end

        # Handle interactive protocols
        @logger.info "[PROTOCOL] #{peer_ip}:#{peer_port} -> #{port} - Starting protocol interaction"
        handle_protocol_interaction(client, port)

      rescue Errno::ECONNRESET, Errno::EPIPE => e
        @logger.info "[RESET] #{peer_ip}:#{peer_port} -> #{port} - Connection reset by peer"
      rescue => e
        @logger.error "[ERROR] #{peer_ip}:#{peer_port} -> #{port} - #{e.message}"
        @logger.debug e.backtrace.join("\n")
      ensure
        duration = Time.now - start_time
        @logger.info "[CLOSE] #{peer_ip}:#{peer_port} -> #{port} - Connection closed (duration: #{duration.round(2)}s)"
        client.close rescue nil
      end
    end
  end

  def handle_filtered_connection(client, port, peer_ip, peer_port)
    Thread.new do
      start_time = Time.now
      begin
        @logger.info "[FILTERED] #{peer_ip}:#{peer_port} -> #{port} - Connection established"

        # Filtered ports accept the connection but don't respond
        # This simulates a firewall dropping packets or a timeout
        # Sleep briefly to simulate network delay/timeout
        timeout = rand(2..5)
        @logger.info "[FILTERED] #{peer_ip}:#{peer_port} -> #{port} - Holding connection for #{timeout}s (no response)"
        sleep(timeout)

        @logger.info "[FILTERED] #{peer_ip}:#{peer_port} -> #{port} - Timeout complete, dropping connection"
      rescue => e
        @logger.error "[ERROR] #{peer_ip}:#{peer_port} -> #{port} - Filtered connection error: #{e.message}"
        @logger.debug e.backtrace.join("\n")
      ensure
        duration = Time.now - start_time
        @logger.info "[CLOSE] #{peer_ip}:#{peer_port} -> #{port} - Filtered connection closed (duration: #{duration.round(2)}s)"
        client.close rescue nil
      end
    end
  end

  def handle_closed_connection(client, port, peer_ip, peer_port)
    Thread.new do
      start_time = Time.now
      begin
        @logger.info "[CLOSED] #{peer_ip}:#{peer_port} -> #{port} - Connection accepted, closing immediately"

        # Closed ports immediately disconnect
        # The TCP stack will send RST packet
        # Just close immediately without any response
        @logger.info "[CLOSED] #{peer_ip}:#{peer_port} -> #{port} - Sending connection termination"
      rescue => e
        @logger.error "[ERROR] #{peer_ip}:#{peer_port} -> #{port} - Closed connection error: #{e.message}"
        @logger.debug e.backtrace.join("\n")
      ensure
        duration = Time.now - start_time
        @logger.info "[CLOSE] #{peer_ip}:#{peer_port} -> #{port} - Closed connection terminated (duration: #{duration.round(3)}s)"
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
      peer = client.peeraddr
      peer_id = "#{peer[3]}:#{peer[1]}"

      @logger.info "[HTTP] #{peer_id} -> #{port} - Waiting for HTTP request"

      # Wait for HTTP request
      request = client.gets
      return unless request

      @logger.info "[RECV] #{peer_id} -> #{port} - Received HTTP request (#{request.bytesize} bytes)"
      @logger.info "[HTTP] #{peer_id} -> #{port} - #{request.strip}"

      # Send proper HTTP response
      response = "HTTP/1.1 200 OK\r\n"
      response << "Server: nginx/1.18.0\r\n"
      response << "Date: #{Time.now.httpdate}\r\n"
      response << "Content-Type: text/html\r\n"
      response << "Content-Length: 91\r\n"
      response << "Connection: close\r\n"
      response << "\r\n"
      response << "<html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>\r\n"

      @logger.info "[SEND] #{peer_id} -> #{port} - Sending HTTP 200 OK response (#{response.bytesize} bytes)"
      client.write(response)
      client.flush
      @logger.info "[HTTP] #{peer_id} -> #{port} - Response sent successfully"
    rescue => e
      @logger.error "[HTTP] Port #{port} error: #{e.message}"
      @logger.debug e.backtrace.join("\n")
    end
  end

  def handle_ssh(client, port)
    # SSH banner already sent, wait for client response
    begin
      peer = client.peeraddr
      peer_id = "#{peer[3]}:#{peer[1]}"

      @logger.info "[SSH] #{peer_id} -> #{port} - Waiting for SSH client negotiation"
      data = client.read_nonblock(255)
      @logger.info "[RECV] #{peer_id} -> #{port} - Received SSH data (#{data.bytesize} bytes)"
      @logger.debug "[SSH] #{peer_id} -> #{port} - Data: #{data.inspect}"

      # Send SSH protocol negotiation failure
      response = "\x00\x00\x00\x0c\x0a\x0e"
      @logger.info "[SEND] #{peer_id} -> #{port} - Sending SSH negotiation failure (#{response.bytesize} bytes)"
      client.write(response)
    rescue IO::WaitReadable
      # Client didn't send anything
      peer = client.peeraddr rescue nil
      if peer
        @logger.info "[SSH] #{peer[3]}:#{peer[1]} -> #{port} - Client sent no data"
      end
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
  
  opts.on("-r", "--range START:END", "Port range (default: 1:10000)") do |range|
    start_port, end_port = range.split(':').map(&:to_i)
    options[:port_range] = (start_port..end_port)
  end
  
  opts.on("-i", "--ip IP", "Bind IP (default: 0.0.0.0)") do |ip|
    options[:bind_ip] = ip
  end
  
  opts.on("-o", "--open PERCENT", Integer, "Open port percentage") do |percent|
    options[:open_chance] = percent
  end
  
  opts.on("-f", "--filtered PERCENT", Integer, "Filtered port percentage") do |percent|
    options[:filtered_chance] = percent
  end
  
  opts.on("-h", "--help", "Show help") do
    puts opts
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

