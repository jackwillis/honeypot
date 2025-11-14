ENV['RACK_ENV'] = 'test'
ENV['MT_NO_PLUGINS'] = '1'  # Disable minitest plugins (avoid Rails plugin conflicts)

require 'minitest/autorun'
require 'mocha/minitest'
require 'rack/test'
require 'json'
require 'fileutils'
require 'timeout'

# Require the application files
require_relative '../honeypot'
require_relative '../lib/honeypot_client'
require_relative '../web_ui'

# Test environment configuration
ENV['WEB_USERNAME'] = 'test_user'
ENV['WEB_PASSWORD'] = 'test_pass'
ENV['WEB_PORT'] = '14167'  # Test port (doesn't conflict)
ENV['WEB_BIND'] = '127.0.0.1'

class Minitest::Test
  # Helper methods for all tests

  def with_temp_socket(&block)
    socket_path = "/tmp/honeypot_test_#{Process.pid}_#{rand(10000)}.sock"

    begin
      yield socket_path
    ensure
      File.delete(socket_path) if File.exist?(socket_path)
    end
  end

  def wait_for_socket(socket_path, timeout: 2)
    Timeout.timeout(timeout) do
      loop do
        break if File.exist?(socket_path)
        sleep 0.01
      end
    end
  rescue Timeout::Error
    raise "Socket #{socket_path} was not created within #{timeout} seconds"
  end

  def create_test_honeypot(options = {})
    # Create honeypot with safe defaults for testing
    default_options = {
      preset: 'nmap-top-200',
      open_chance: 70,
      filtered_chance: 20,
      rotation_interval: 10,
      logger: Logger.new(nil)  # Silent logger for clean test output
    }

    Honeypot.new(default_options.merge(options))
  end

  # Helper to stub TCPServer to avoid real port binding
  def stub_tcp_server
    mock_server = mock('TCPServer')
    mock_server.stubs(:setsockopt)
    mock_server.stubs(:close)
    mock_server.stubs(:accept).raises(IOError) # Exit listener loops

    TCPServer.stubs(:new).returns(mock_server)

    mock_server
  end

  # Helper to create a mock thread that can be tracked
  def mock_thread(name = 'test_thread')
    thread = mock(name)
    thread.stubs(:alive?).returns(true)
    thread.stubs(:join)
    thread
  end
end

# Module for shared test data
module TestFixtures
  def sample_connection_data
    {
      timestamp: Time.now.iso8601,
      source: '192.168.1.100:54321',
      port: 8080,
      state: 'open'
    }
  end

  def sample_status_data
    {
      running: true,
      uptime: 3600,
      ports_bound: 140,
      ports_total: 200,
      last_rotation: 12,
      rotation_count: 15,
      rotation_interval: 10,
      open_percentage: 70,
      filtered_percentage: 20,
      connections_today: 42
    }
  end

  def sample_ports_data
    {
      bound: [22, 80, 443, 3306, 8080],
      unbound: [21, 23, 25, 110, 143],
      well_known: [22, 80, 443, 3306]
    }
  end
end
