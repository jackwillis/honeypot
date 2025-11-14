require_relative '../test_helper'

class TestHoneypotClient < Minitest::Test
  include TestFixtures

  def test_initialization_with_default_socket_path
    client = HoneypotClient.new

    assert_equal '/tmp/honeypot.sock', client.instance_variable_get(:@socket_path)
  end

  def test_initialization_with_custom_socket_path
    client = HoneypotClient.new(socket_path: '/custom/path.sock')

    assert_equal '/custom/path.sock', client.instance_variable_get(:@socket_path)
  end

  def test_send_command_raises_error_if_socket_missing
    client = HoneypotClient.new(socket_path: '/nonexistent/socket.sock')

    error = assert_raises(HoneypotClient::ConnectionError) do
      client.status
    end

    assert_match /socket not found/i, error.message
  end

  def test_send_command_builds_correct_json_request
    with_temp_socket do |socket_path|
      # Create mock server
      mock_server = mock_unix_server(socket_path) do |request_json|
        request = JSON.parse(request_json)

        assert_equal 'get_status', request['action']
        assert_kind_of Hash, request['payload']
        assert_kind_of Integer, request['timestamp']

        # Return mock response
        { data: sample_status_data }.to_json
      end

      client = HoneypotClient.new(socket_path: socket_path)
      result = client.status

      assert_equal sample_status_data[:ports_bound], result[:ports_bound]

      mock_server.close
      File.delete(socket_path) if File.exist?(socket_path)
    end
  end

  def test_status_command
    with_temp_socket do |socket_path|
      mock_server = mock_unix_server(socket_path) do |request|
        req = JSON.parse(request)
        assert_equal 'get_status', req['action']
        { data: sample_status_data }.to_json
      end

      client = HoneypotClient.new(socket_path: socket_path)
      status = client.status

      assert_equal 140, status[:ports_bound]
      assert_equal 200, status[:ports_total]

      mock_server.close
    end
  end

  def test_update_config_command
    with_temp_socket do |socket_path|
      mock_server = mock_unix_server(socket_path) do |request|
        req = JSON.parse(request)
        assert_equal 'update_config', req['action']
        assert_equal 99, req['payload']['rotation_interval']
        { data: { success: true } }.to_json
      end

      client = HoneypotClient.new(socket_path: socket_path)
      result = client.update_config(rotation_interval: 99)

      assert_equal true, result[:success]

      mock_server.close
    end
  end

  def test_recent_connections_command_with_limit
    with_temp_socket do |socket_path|
      mock_server = mock_unix_server(socket_path) do |request|
        req = JSON.parse(request)
        assert_equal 'get_connections', req['action']
        assert_equal 25, req['payload']['limit']
        { data: [sample_connection_data] }.to_json
      end

      client = HoneypotClient.new(socket_path: socket_path)
      connections = client.recent_connections(limit: 25)

      assert_equal 1, connections.size

      mock_server.close
    end
  end

  def test_current_ports_command
    with_temp_socket do |socket_path|
      mock_server = mock_unix_server(socket_path) do |request|
        req = JSON.parse(request)
        assert_equal 'get_ports', req['action']
        { data: sample_ports_data }.to_json
      end

      client = HoneypotClient.new(socket_path: socket_path)
      ports = client.current_ports

      assert_equal [22, 80, 443, 3306, 8080], ports[:bound]

      mock_server.close
    end
  end

  def test_rotate_now_command
    with_temp_socket do |socket_path|
      mock_server = mock_unix_server(socket_path) do |request|
        req = JSON.parse(request)
        assert_equal 'rotate_now', req['action']
        { data: { success: true, message: "Rotation triggered" } }.to_json
      end

      client = HoneypotClient.new(socket_path: socket_path)
      result = client.rotate_now

      assert_equal true, result[:success]

      mock_server.close
    end
  end

  def test_ping_command_returns_true_when_connected
    with_temp_socket do |socket_path|
      mock_server = mock_unix_server(socket_path) do |request|
        { data: { pong: true, timestamp: Time.now.to_i } }.to_json
      end

      client = HoneypotClient.new(socket_path: socket_path)
      result = client.ping

      assert_equal true, result[:pong]

      mock_server.close
    end
  end

  def test_ping_returns_false_on_connection_error
    client = HoneypotClient.new(socket_path: '/nonexistent.sock')

    assert_equal false, client.ping
  end

  def test_error_response_raises_exception
    with_temp_socket do |socket_path|
      mock_server = mock_unix_server(socket_path) do |request|
        { error: "Something went wrong" }.to_json
      end

      client = HoneypotClient.new(socket_path: socket_path)

      error = assert_raises(HoneypotClient::ConnectionError) do
        client.status
      end

      assert_match /Something went wrong/, error.message

      mock_server.close
    end
  end

  private

  # Helper to create a mock Unix server for testing
  def mock_unix_server(socket_path, &response_block)
    server = UNIXServer.new(socket_path)
    File.chmod(0666, socket_path)

    # Start server in background thread
    Thread.new do
      begin
        client = server.accept
        request = client.gets
        response = response_block.call(request)
        client.puts(response)
        client.close
      rescue => e
        # Ignore errors in test server
      end
    end

    sleep 0.01 # Let server start

    server
  end
end
