require 'active_record'

class Connection < ActiveRecord::Base
  # Validations
  validates :source_ip, :dest_port, :state, :timestamp, presence: true
  validates :state, inclusion: { in: %w[open filtered closed] }
  validates :dest_port, numericality: { only_integer: true, greater_than: 0, less_than_or_equal_to: 65535 }

  # Scopes
  scope :recent, ->(limit = 50) { order(timestamp: :desc).limit(limit) }
  scope :by_port, ->(port) { where(dest_port: port) }
  scope :by_ip, ->(ip) { where(source_ip: ip) }
  scope :by_state, ->(state) { where(state: state) }
  scope :today, -> { where('timestamp >= ?', Time.now.beginning_of_day) }
  scope :last_24h, -> { where('timestamp >= ?', Time.now - 24 * 60 * 60) }

  # Class methods for statistics
  def self.top_ports(limit: 10)
    group(:dest_port)
      .select('dest_port, COUNT(*) as connection_count')
      .order('connection_count DESC')
      .limit(limit)
      .map { |c| { port: c.dest_port, count: c.connection_count } }
  end

  def self.top_ips(limit: 10)
    group(:source_ip)
      .select('source_ip, COUNT(*) as connection_count')
      .order('connection_count DESC')
      .limit(limit)
      .map { |c| { ip: c.source_ip, count: c.connection_count } }
  end

  def self.state_distribution
    group(:state)
      .select('state, COUNT(*) as count')
      .map { |c| [c.state, c.count] }
      .to_h
  end

  def self.hourly_activity(hours: 24)
    where('timestamp >= ?', Time.now - hours * 60 * 60)
      .group_by { |c| c.timestamp.strftime('%Y-%m-%d %H:00') }
      .transform_values(&:count)
  end

  # Instance methods
  def to_hash
    {
      id: id,
      timestamp: timestamp.iso8601,
      source_ip: source_ip,
      source_port: source_port,
      dest_port: dest_port,
      protocol: protocol,
      state: state,
      duration: duration,
      banner_sent: banner_sent,
      service: service
    }
  end

  # Quick logging helper
  def self.log_connection!(source_ip:, source_port:, dest_port:, state:, duration: nil, banner: nil, service: nil)
    create!(
      timestamp: Time.now,
      source_ip: source_ip,
      source_port: source_port,
      dest_port: dest_port,
      state: state,
      duration: duration,
      banner_sent: banner,
      service: service
    )
  end
end
