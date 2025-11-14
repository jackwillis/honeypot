# Database schema for honeypot connection logging
# This file is loaded by db/setup.rb

ActiveRecord::Schema.define do
  create_table :connections, if_not_exists: true do |t|
    t.datetime :timestamp, null: false, index: true
    t.string :source_ip, null: false, index: true
    t.integer :source_port
    t.integer :dest_port, null: false, index: true
    t.string :protocol, default: 'tcp'
    t.string :state, null: false  # 'open', 'filtered', 'closed'
    t.float :duration
    t.text :banner_sent
    t.string :service  # SSH, HTTP, MySQL, etc.

    t.timestamps null: false
  end

  # Index for common queries
  add_index :connections, [:timestamp, :source_ip], if_not_exists: true
  add_index :connections, [:dest_port, :state], if_not_exists: true
end
