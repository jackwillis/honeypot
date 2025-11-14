require 'active_record'
require 'logger'

module HoneypotDB
  # Database configuration
  def self.database_path
    if ENV['RACK_ENV'] == 'production'
      '/var/lib/honeypot/connections.db'
    else
      File.join(__dir__, 'connections.db')
    end
  end

  # Connect to database
  def self.connect!
    ActiveRecord::Base.establish_connection(
      adapter: 'sqlite3',
      database: database_path,
      pool: 5,
      timeout: 5000
    )

    # Enable logging in development
    unless ENV['RACK_ENV'] == 'production'
      ActiveRecord::Base.logger = Logger.new(STDOUT)
      ActiveRecord::Base.logger.level = Logger::WARN
    end
  end

  # Create tables from schema
  def self.setup!
    connect!

    # Ensure database directory exists
    db_dir = File.dirname(database_path)
    Dir.mkdir(db_dir, 0755) unless Dir.exist?(db_dir)

    # Load and execute schema
    load File.join(__dir__, 'schema.rb')
  end

  # Database maintenance
  def self.cleanup_old_connections!(days: 90)
    cutoff = Time.now - (days * 24 * 60 * 60)
    deleted = Connection.where('timestamp < ?', cutoff).delete_all
    ActiveRecord::Base.connection.execute('VACUUM')
    deleted
  end

  def self.stats
    {
      total_connections: Connection.count,
      unique_ips: Connection.distinct.count(:source_ip),
      database_size: File.size(database_path),
      oldest_record: Connection.order(:timestamp).first&.timestamp,
      newest_record: Connection.order(:timestamp).last&.timestamp
    }
  end
end
