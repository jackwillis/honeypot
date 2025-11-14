require_relative '../test_helper'

class TestIPCCommunication < Minitest::Test
  def setup
    @socket_path = "/tmp/honeypot_test_#{Process.pid}_#{rand(10000)}.sock"
    @honeypot = create_test_honeypot

    # Start Unix socket server
    @honeypot.send(:start_unix_socket_server, @socket_path)
    wait_for_socket(@socket_path)

    @client = HoneypotClient.new(socket_path: @socket_path)
  end

  def teardown
    # Stop honeypot
    @honeypot.instance_variable_set(:@running, false)
    sleep 0.1

    # Clean up socket
    File.delete(@socket_path) if File.exist?(@socket_path)
  end

  def test_client_can_connect_to_honeypot
    # Just pinging should work
    result = @client.ping

    assert_equal true, result[:pong]
    assert_kind_of Integer, result[:timestamp]
  end

  def test_get_status_returns_valid_data
    status = @client.status

    assert_kind_of Integer, status[:uptime]
    assert status[:uptime] >= 0

    assert_kind_of Integer, status[:ports_bound]
    assert_kind_of Integer, status[:ports_total]

    assert_kind_of Integer, status[:rotation_interval]
    assert_kind_of Integer, status[:open_percentage]
    assert_kind_of Integer, status[:filtered_percentage]
  end

  def test_update_config_changes_honeypot_settings
    @client.update_config(
      rotation_interval: 99,
      open_percentage: 85,
      filtered_percentage: 10
    )

    # Verify changes in honeypot
    assert_equal 99, @honeypot.instance_variable_get(:@rotation_interval)
    assert_equal 85, @honeypot.instance_variable_get(:@open_chance)
    assert_equal 10, @honeypot.instance_variable_get(:@filtered_chance)
  end

  def test_update_config_reflected_in_status
    @client.update_config(rotation_interval: 77)

    status = @client.status

    assert_equal 77, status[:rotation_interval]
  end

  def test_get_connections_initially_empty
    connections = @client.recent_connections

    assert_kind_of Array, connections
    # Should be empty initially (no real connections in test)
    assert_equal 0, connections.size
  end

  def test_get_connections_after_logging
    # Manually log some connections in honeypot
    5.times do |i|
      @honeypot.send(:log_connection, '10.0.0.1', 50000 + i, 8080, :open)
    end

    connections = @client.recent_connections

    assert_equal 5, connections.size

    conn = connections.first
    assert_equal '10.0.0.1:50000', conn[:source]
    assert_equal 8080, conn[:port]
    assert_equal 'open', conn[:state]
  end

  def test_get_connections_respects_limit
    # Add 20 connections
    20.times do |i|
      @honeypot.send(:log_connection, '10.0.0.1', 50000 + i, 8080, :open)
    end

    connections = @client.recent_connections(limit: 10)

    assert_equal 10, connections.size
  end

  def test_get_current_ports
    # Set up some port state
    @honeypot.instance_variable_set(:@currently_bound, Set.new([22, 80, 443, 8080]))
    @honeypot.instance_variable_set(:@currently_unbound, Set.new([21, 23, 25]))
    @honeypot.instance_variable_set(:@well_known_ports, Set.new([22, 80, 443]))

    ports = @client.current_ports

    assert_kind_of Hash, ports
    assert_includes ports[:bound], 22
    assert_includes ports[:bound], 80
    assert_includes ports[:well_known], 22
    assert_includes ports[:unbound], 21
  end

  def test_rotate_now_triggers_rotation
    initial_count = @honeypot.instance_variable_get(:@rotation_count)

    # Set up minimal state for rotation to work
    @honeypot.instance_variable_set(:@currently_bound, Set.new([80, 443, 8080, 8081, 8082]))
    @honeypot.instance_variable_set(:@currently_unbound, Set.new([22, 23, 25, 110, 143]))
    @honeypot.instance_variable_set(:@well_known_ports, Set.new([80, 443, 22]))

    # Stub to avoid real port operations
    @honeypot.stubs(:bind_port).returns(true)
    @honeypot.stubs(:unbind_port).returns(true)

    result = @client.rotate_now

    assert_equal true, result[:success]

    new_count = @honeypot.instance_variable_get(:@rotation_count)
    assert_equal initial_count + 1, new_count
  end

  def test_multiple_sequential_requests
    # Test that multiple requests work correctly
    3.times do
      status = @client.status
      assert_kind_of Integer, status[:uptime]
    end
  end

  def test_invalid_action_returns_error
    # Manually send invalid command
    socket = UNIXSocket.new(@socket_path)
    socket.puts({ action: 'invalid_command', payload: {} }.to_json)

    response = JSON.parse(socket.gets, symbolize_names: true)

    assert response[:error]
    assert_match /Unknown action/, response[:error]

    socket.close
  end

  def test_malformed_json_returns_error
    socket = UNIXSocket.new(@socket_path)
    socket.puts("this is not json")

    response = JSON.parse(socket.gets, symbolize_names: true)

    assert response[:error]
    assert_match /Invalid JSON/, response[:error]

    socket.close
  end
end
