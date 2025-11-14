require_relative '../test_helper'

class TestHoneypot < Minitest::Test
  def setup
    @honeypot = create_test_honeypot
  end

  def test_initialization_with_defaults
    honeypot = Honeypot.new(preset: 'nmap-top-200', logger: Logger.new(nil))

    assert_equal 70, honeypot.instance_variable_get(:@open_chance)
    assert_equal 20, honeypot.instance_variable_get(:@filtered_chance)
    assert_equal 10, honeypot.instance_variable_get(:@rotation_interval)
    assert_equal '0.0.0.0', honeypot.instance_variable_get(:@bind_ip)
  end

  def test_initialization_with_custom_options
    honeypot = Honeypot.new(
      preset: 'nmap-top-200',
      open_chance: 80,
      filtered_chance: 15,
      rotation_interval: 5,
      bind_ip: '127.0.0.1',
      logger: Logger.new(nil)
    )

    assert_equal 80, honeypot.instance_variable_get(:@open_chance)
    assert_equal 15, honeypot.instance_variable_get(:@filtered_chance)
    assert_equal 5, honeypot.instance_variable_get(:@rotation_interval)
    assert_equal '127.0.0.1', honeypot.instance_variable_get(:@bind_ip)
  end

  def test_get_preset_ports_nmap_top_200
    ports = @honeypot.send(:get_preset_ports, 'nmap-top-200')

    assert_equal Honeypot::NMAP_TOP_200, ports
    assert_equal 212, ports.size  # Actually 212 ports in the list
    assert_includes ports, 22  # SSH
    assert_includes ports, 80  # HTTP
    assert_includes ports, 443 # HTTPS
  end

  def test_get_preset_ports_all
    ports = @honeypot.send(:get_preset_ports, 'all')

    assert_kind_of Range, ports
    assert_equal 1, ports.first
    assert_equal 65535, ports.last
  end

  def test_log_connection_adds_to_history
    @honeypot.send(:log_connection, '192.168.1.100', 54321, 8080, :open)

    history = @honeypot.instance_variable_get(:@connection_history)

    assert_equal 1, history.size
    conn = history.first

    assert_equal '192.168.1.100:54321', conn[:source]
    assert_equal 8080, conn[:port]
    assert_equal 'open', conn[:state]
    assert conn[:timestamp]
  end

  def test_log_connection_limits_history_to_100
    # Add 150 connections
    150.times do |i|
      @honeypot.send(:log_connection, '10.0.0.1', 50000 + i, 8080, :open)
    end

    history = @honeypot.instance_variable_get(:@connection_history)

    assert_equal 100, history.size
  end

  def test_get_current_status_returns_hash
    status = @honeypot.send(:get_current_status)

    assert_kind_of Hash, status
    assert_includes status.keys, :running
    assert_includes status.keys, :uptime
    assert_includes status.keys, :ports_bound
    assert_includes status.keys, :ports_total
    assert_includes status.keys, :rotation_interval
    assert_includes status.keys, :open_percentage
    assert_includes status.keys, :filtered_percentage
  end

  def test_update_runtime_config_changes_settings
    result = @honeypot.send(:update_runtime_config,
      rotation_interval: 99,
      open_percentage: 88,
      filtered_percentage: 11
    )

    assert_equal 99, @honeypot.instance_variable_get(:@rotation_interval)
    assert_equal 88, @honeypot.instance_variable_get(:@open_chance)
    assert_equal 11, @honeypot.instance_variable_get(:@filtered_chance)
    assert_equal true, result[:success]
  end

  def test_update_runtime_config_ignores_nil_values
    original_interval = @honeypot.instance_variable_get(:@rotation_interval)

    @honeypot.send(:update_runtime_config, rotation_interval: nil, open_percentage: 75)

    assert_equal original_interval, @honeypot.instance_variable_get(:@rotation_interval)
    assert_equal 75, @honeypot.instance_variable_get(:@open_chance)
  end

  def test_get_recent_connections_with_limit
    # Add some connections
    10.times do |i|
      @honeypot.send(:log_connection, '10.0.0.1', 50000 + i, 8080, :open)
    end

    recent = @honeypot.send(:get_recent_connections, 5)

    assert_equal 5, recent.size
  end

  def test_get_current_ports_returns_hash
    # Manually set some ports for testing
    @honeypot.instance_variable_set(:@currently_bound, Set.new([80, 443, 8080]))
    @honeypot.instance_variable_set(:@currently_unbound, Set.new([22, 23, 25]))
    @honeypot.instance_variable_set(:@well_known_ports, Set.new([80, 443]))

    ports = @honeypot.send(:get_current_ports)

    assert_kind_of Hash, ports
    assert_equal [80, 443, 8080], ports[:bound].sort
    assert_equal [22, 23, 25], ports[:unbound].sort
    assert_equal [80, 443], ports[:well_known].sort
  end

  def test_rotation_count_increments
    initial_count = @honeypot.instance_variable_get(:@rotation_count)

    # Manually set up minimal state for rotation
    @honeypot.instance_variable_set(:@currently_bound, Set.new([80, 443, 8080, 8081, 8082]))
    @honeypot.instance_variable_set(:@currently_unbound, Set.new([22, 23, 25, 110, 143]))
    @honeypot.instance_variable_set(:@well_known_ports, Set.new([80, 443, 22]))

    # Stub bind/unbind to avoid real operations
    @honeypot.stubs(:bind_port).returns(true)
    @honeypot.stubs(:unbind_port).returns(true)

    @honeypot.send(:rotate_ports)

    new_count = @honeypot.instance_variable_get(:@rotation_count)
    assert_equal initial_count + 1, new_count
  end

  def test_service_name_returns_known_services
    assert_equal 'SSH', @honeypot.send(:service_name, 22)
    assert_equal 'HTTP', @honeypot.send(:service_name, 80)
    assert_equal 'HTTPS', @honeypot.send(:service_name, 443)
    assert_equal 'MySQL', @honeypot.send(:service_name, 3306)
    assert_equal 'Unknown', @honeypot.send(:service_name, 12345)
  end

  def test_generate_banner_for_ssh
    banner = @honeypot.send(:generate_banner, 22)

    assert_match /SSH-2\.0-OpenSSH/, banner
    assert_match /\r\n\z/, banner  # Ends with CRLF
  end

  def test_generate_banner_for_ftp
    banner = @honeypot.send(:generate_banner, 21)

    assert_match /220/, banner
    assert_match /vsFTPd/, banner
  end

  def test_generate_banner_returns_nil_for_binary_protocols
    assert_nil @honeypot.send(:generate_banner, 3306)  # MySQL
    assert_nil @honeypot.send(:generate_banner, 5432)  # PostgreSQL
    assert_nil @honeypot.send(:generate_banner, 443)   # HTTPS
  end
end
