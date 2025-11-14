require 'socket'
require 'json'

class HoneypotClient
  SOCKET_PATH = '/tmp/honeypot.sock'
  TIMEOUT = 5 # seconds

  class ConnectionError < StandardError; end
  class TimeoutError < StandardError; end

  def initialize(socket_path: SOCKET_PATH)
    @socket_path = socket_path
  end

  # Get current honeypot status
  def status
    send_command('get_status')
  end

  # Update honeypot configuration
  def update_config(**config)
    send_command('update_config', config)
  end

  # Get recent connections
  def recent_connections(limit: 50)
    send_command('get_connections', { limit: limit })
  end

  # Get currently bound ports
  def current_ports
    send_command('get_ports')
  end

  # Trigger immediate port rotation
  def rotate_now
    send_command('rotate_now')
  end

  # Check if honeypot is running
  def ping
    send_command('ping')
  rescue ConnectionError
    false
  end

  private

  def send_command(action, payload = {})
    unless File.exist?(@socket_path)
      raise ConnectionError, "Honeypot socket not found at #{@socket_path}. Is the honeypot running?"
    end

    socket = UNIXSocket.new(@socket_path)

    # Send command as JSON
    request = {
      action: action,
      payload: payload,
      timestamp: Time.now.to_i
    }.to_json

    socket.puts(request)

    # Read response with timeout
    if IO.select([socket], nil, nil, TIMEOUT)
      response_data = socket.gets
      raise ConnectionError, "No response from honeypot" unless response_data

      response = JSON.parse(response_data, symbolize_names: true)

      if response[:error]
        raise ConnectionError, "Honeypot error: #{response[:error]}"
      end

      response[:data]
    else
      raise TimeoutError, "Honeypot did not respond within #{TIMEOUT} seconds"
    end
  rescue Errno::ENOENT
    raise ConnectionError, "Socket file does not exist: #{@socket_path}"
  rescue Errno::ECONNREFUSED
    raise ConnectionError, "Connection refused. Is the honeypot running?"
  rescue JSON::ParserError => e
    raise ConnectionError, "Invalid response from honeypot: #{e.message}"
  ensure
    socket&.close
  end
end
