require 'sinatra/base'
require 'json'
require_relative 'lib/honeypot_client'

class HoneypotWebUI < Sinatra::Base
  # Configuration
  set :port, ENV.fetch('WEB_PORT', 4167)
  set :bind, ENV.fetch('WEB_BIND', '127.0.0.1')
  set :server, 'puma'

  # Basic Authentication
  use Rack::Auth::Basic, "Honeypot Control Panel" do |username, password|
    username == ENV.fetch('WEB_USERNAME', 'admin') &&
    password == ENV.fetch('WEB_PASSWORD', 'change_me')
  end

  # Initialize honeypot client
  def client
    @client ||= HoneypotClient.new
  end

  # Helper to format duration
  helpers do
    def format_duration(seconds)
      hours = seconds / 3600
      minutes = (seconds % 3600) / 60
      secs = seconds % 60

      if hours > 0
        "#{hours}h #{minutes}m"
      elsif minutes > 0
        "#{minutes}m #{secs}s"
      else
        "#{secs}s"
      end
    end

    def format_timestamp(iso_timestamp)
      Time.parse(iso_timestamp).strftime('%H:%M:%S')
    rescue
      iso_timestamp
    end

    def state_class(state)
      case state
      when 'open' then 'open'
      when 'filtered' then 'filtered'
      when 'closed' then 'closed'
      else 'unknown'
      end
    end
  end

  # Routes
  get '/' do
    redirect '/dashboard'
  end

  get '/dashboard' do
    begin
      @status = client.status
      @connections = client.recent_connections(limit: 50)
      erb :dashboard
    rescue HoneypotClient::ConnectionError => e
      erb :error, locals: { error_message: e.message }
    end
  end

  get '/settings' do
    begin
      @status = client.status
      erb :settings
    rescue HoneypotClient::ConnectionError => e
      erb :error, locals: { error_message: e.message }
    end
  end

  post '/settings' do
    begin
      config = {
        rotation_interval: params[:rotation_interval],
        open_percentage: params[:open_percentage],
        filtered_percentage: params[:filtered_percentage]
      }

      client.update_config(**config)
      redirect '/settings?success=1'
    rescue HoneypotClient::ConnectionError => e
      redirect '/settings?error=' + CGI.escape(e.message)
    end
  end

  post '/scenarios/:name' do
    begin
      scenario = params[:name]

      config = case scenario
      when 'cloud'
        { rotation_interval: 5, open_percentage: 80, filtered_percentage: 15 }
      when 'datacenter'
        { rotation_interval: 60, open_percentage: 40, filtered_percentage: 30 }
      when 'hybrid'
        { rotation_interval: 15, open_percentage: 60, filtered_percentage: 20 }
      else
        halt 400, "Unknown scenario: #{scenario}"
      end

      client.update_config(**config)
      redirect '/settings?success=1&scenario=' + scenario
    rescue HoneypotClient::ConnectionError => e
      redirect '/settings?error=' + CGI.escape(e.message)
    end
  end

  post '/rotate' do
    begin
      client.rotate_now
      redirect '/dashboard?rotated=1'
    rescue HoneypotClient::ConnectionError => e
      redirect '/dashboard?error=' + CGI.escape(e.message)
    end
  end

  # API endpoints (JSON)
  get '/api/status' do
    content_type :json
    begin
      client.status.to_json
    rescue HoneypotClient::ConnectionError => e
      status 503
      { error: e.message }.to_json
    end
  end

  get '/api/connections' do
    content_type :json
    begin
      limit = params[:limit]&.to_i || 50
      client.recent_connections(limit: limit).to_json
    rescue HoneypotClient::ConnectionError => e
      status 503
      { error: e.message }.to_json
    end
  end

  get '/api/ports' do
    content_type :json
    begin
      client.current_ports.to_json
    rescue HoneypotClient::ConnectionError => e
      status 503
      { error: e.message }.to_json
    end
  end

  # Health check
  get '/health' do
    content_type :json
    begin
      if client.ping
        { status: 'healthy', honeypot: 'connected' }.to_json
      else
        status 503
        { status: 'unhealthy', honeypot: 'not responding' }.to_json
      end
    rescue
      status 503
      { status: 'unhealthy', honeypot: 'disconnected' }.to_json
    end
  end

  # 404 handler
  not_found do
    'Page not found'
  end

  # Error handler
  error do
    'Internal server error'
  end
end

# Run the app if this file is executed directly
if __FILE__ == $0
  HoneypotWebUI.run!
end
