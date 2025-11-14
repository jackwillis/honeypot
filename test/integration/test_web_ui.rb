require_relative '../test_helper'

class TestWebUI < Minitest::Test
  include Rack::Test::Methods
  include TestFixtures

  def app
    HoneypotWebUI
  end

  def setup
    # Mock the HoneypotClient for all tests
    @mock_client = mock('HoneypotClient')
    HoneypotClient.stubs(:new).returns(@mock_client)
  end

  # Authentication Tests

  def test_dashboard_requires_authentication
    get '/dashboard'

    assert_equal 401, last_response.status
  end

  def test_settings_requires_authentication
    get '/settings'

    assert_equal 401, last_response.status
  end

  def test_api_endpoints_require_authentication
    get '/api/status'

    assert_equal 401, last_response.status
  end

  def test_authentication_with_valid_credentials
    @mock_client.stubs(:status).returns(sample_status_data)
    @mock_client.stubs(:recent_connections).returns([])

    authorize 'test_user', 'test_pass'
    get '/dashboard'

    assert last_response.ok?
  end

  def test_authentication_rejects_invalid_credentials
    authorize 'wrong', 'credentials'
    get '/dashboard'

    assert_equal 401, last_response.status
  end

  # Dashboard Tests

  def test_dashboard_renders_successfully
    @mock_client.stubs(:status).returns(sample_status_data)
    @mock_client.stubs(:recent_connections).returns([sample_connection_data])

    authorize 'test_user', 'test_pass'
    get '/dashboard'

    assert last_response.ok?
    assert_includes last_response.body, 'Honeypot Dashboard'
    assert_includes last_response.body, '140'  # ports_bound from sample data
  end

  def test_dashboard_displays_connections
    @mock_client.stubs(:status).returns(sample_status_data)
    @mock_client.stubs(:recent_connections).returns([sample_connection_data])

    authorize 'test_user', 'test_pass'
    get '/dashboard'

    assert_includes last_response.body, '192.168.1.100:54321'
    assert_includes last_response.body, '8080'
  end

  def test_dashboard_handles_ipc_error
    @mock_client.stubs(:status).raises(HoneypotClient::ConnectionError, 'Socket not found')

    authorize 'test_user', 'test_pass'
    get '/dashboard'

    assert last_response.ok?  # Still renders
    assert_includes last_response.body, 'Socket not found'
  end

  # Settings Tests

  def test_settings_page_renders
    @mock_client.stubs(:status).returns(sample_status_data)

    authorize 'test_user', 'test_pass'
    get '/settings'

    assert last_response.ok?
    assert_includes last_response.body, 'Honeypot Settings'
    assert_includes last_response.body, '70'  # open_percentage
  end

  def test_post_settings_updates_config
    @mock_client.expects(:update_config).with(
      rotation_interval: '15',
      open_percentage: '75',
      filtered_percentage: '25'
    ).returns({ success: true })

    authorize 'test_user', 'test_pass'
    post '/settings', {
      rotation_interval: 15,
      open_percentage: 75,
      filtered_percentage: 25
    }

    assert_equal 302, last_response.status  # Redirect
    assert_includes last_response.location, '/settings?success=1'
  end

  def test_post_settings_handles_ipc_error
    @mock_client.stubs(:update_config).raises(HoneypotClient::ConnectionError, 'Connection failed')

    authorize 'test_user', 'test_pass'
    post '/settings', { rotation_interval: 15 }

    assert_equal 302, last_response.status
    assert_includes last_response.location, 'error='
  end

  # Scenario Tests

  def test_cloud_scenario_applies_correct_config
    @mock_client.expects(:update_config).with(
      rotation_interval: 5,
      open_percentage: 80,
      filtered_percentage: 15
    ).returns({ success: true })

    authorize 'test_user', 'test_pass'
    post '/scenarios/cloud'

    assert_equal 302, last_response.status
    assert_includes last_response.location, 'scenario=cloud'
  end

  def test_datacenter_scenario_applies_correct_config
    @mock_client.expects(:update_config).with(
      rotation_interval: 60,
      open_percentage: 40,
      filtered_percentage: 30
    ).returns({ success: true })

    authorize 'test_user', 'test_pass'
    post '/scenarios/datacenter'

    assert_equal 302, last_response.status
  end

  def test_hybrid_scenario_applies_correct_config
    @mock_client.expects(:update_config).with(
      rotation_interval: 15,
      open_percentage: 60,
      filtered_percentage: 20
    ).returns({ success: true })

    authorize 'test_user', 'test_pass'
    post '/scenarios/hybrid'

    assert_equal 302, last_response.status
  end

  def test_unknown_scenario_returns_400
    authorize 'test_user', 'test_pass'
    post '/scenarios/unknown'

    assert_equal 400, last_response.status
  end

  # Rotate Action Test

  def test_rotate_triggers_rotation
    @mock_client.expects(:rotate_now).returns({ success: true })

    authorize 'test_user', 'test_pass'
    post '/rotate'

    assert_equal 302, last_response.status
    assert_includes last_response.location, '/dashboard?rotated=1'
  end

  # API Endpoint Tests

  def test_api_status_returns_json
    @mock_client.stubs(:status).returns(sample_status_data)

    authorize 'test_user', 'test_pass'
    get '/api/status'

    assert_equal 'application/json', last_response.content_type
    data = JSON.parse(last_response.body, symbolize_names: true)

    assert_equal 140, data[:ports_bound]
    assert_equal 200, data[:ports_total]
  end

  def test_api_status_handles_ipc_error
    @mock_client.stubs(:status).raises(HoneypotClient::ConnectionError, 'IPC failed')

    authorize 'test_user', 'test_pass'
    get '/api/status'

    assert_equal 503, last_response.status
    data = JSON.parse(last_response.body, symbolize_names: true)

    assert data[:error]
    assert_match /IPC failed/, data[:error]
  end

  def test_api_connections_returns_json_array
    connections = [sample_connection_data, sample_connection_data]
    @mock_client.stubs(:recent_connections).with(limit: 50).returns(connections)

    authorize 'test_user', 'test_pass'
    get '/api/connections'

    assert_equal 'application/json', last_response.content_type
    data = JSON.parse(last_response.body)

    assert_equal 2, data.size
  end

  def test_api_connections_respects_limit_parameter
    @mock_client.expects(:recent_connections).with(limit: 100).returns([])

    authorize 'test_user', 'test_pass'
    get '/api/connections?limit=100'

    assert last_response.ok?
  end

  def test_api_ports_returns_port_data
    @mock_client.stubs(:current_ports).returns(sample_ports_data)

    authorize 'test_user', 'test_pass'
    get '/api/ports'

    assert_equal 'application/json', last_response.content_type
    data = JSON.parse(last_response.body, symbolize_names: true)

    assert_includes data[:bound], 22
    assert_includes data[:well_known], 80
  end

  # Health Check Test

  def test_health_endpoint_when_honeypot_responding
    @mock_client.stubs(:ping).returns(true)

    authorize 'test_user', 'test_pass'
    get '/health'

    assert last_response.ok?
    data = JSON.parse(last_response.body, symbolize_names: true)

    assert_equal 'healthy', data[:status]
    assert_equal 'connected', data[:honeypot]
  end

  def test_health_endpoint_when_honeypot_not_responding
    @mock_client.stubs(:ping).returns(false)

    authorize 'test_user', 'test_pass'
    get '/health'

    assert_equal 503, last_response.status
    data = JSON.parse(last_response.body, symbolize_names: true)

    assert_equal 'unhealthy', data[:status]
  end

  def test_health_endpoint_when_ipc_disconnected
    @mock_client.stubs(:ping).raises(HoneypotClient::ConnectionError)

    authorize 'test_user', 'test_pass'
    get '/health'

    assert_equal 503, last_response.status
    data = JSON.parse(last_response.body, symbolize_names: true)

    assert_equal 'disconnected', data[:honeypot]
  end

  # Route Tests

  def test_root_redirects_to_dashboard
    authorize 'test_user', 'test_pass'
    get '/'

    assert_equal 302, last_response.status
    assert_includes last_response.location, '/dashboard'
  end

  def test_404_for_unknown_route
    authorize 'test_user', 'test_pass'
    get '/nonexistent'

    assert_equal 404, last_response.status
  end
end
