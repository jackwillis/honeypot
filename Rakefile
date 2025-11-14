require 'rake/testtask'

# Default task
task default: :test

# Run all tests
Rake::TestTask.new(:test) do |t|
  t.libs << 'test'
  t.libs << 'lib'
  t.test_files = FileList['test/**/test_*.rb']
  t.verbose = true
  t.warning = false
end

# Run only unit tests
Rake::TestTask.new(:test_unit) do |t|
  t.libs << 'test'
  t.libs << 'lib'
  t.test_files = FileList['test/unit/test_*.rb']
  t.verbose = true
  t.warning = false
end

# Run only integration tests
Rake::TestTask.new(:test_integration) do |t|
  t.libs << 'test'
  t.libs << 'lib'
  t.test_files = FileList['test/integration/test_*.rb']
  t.verbose = true
  t.warning = false
end

# Run tests with verbose output
Rake::TestTask.new(:test_verbose) do |t|
  t.libs << 'test'
  t.libs << 'lib'
  t.test_files = FileList['test/**/test_*.rb']
  t.verbose = true
  t.warning = true
end

desc "List all available test tasks"
task :test_tasks do
  puts "Available test tasks:"
  puts "  rake test              # Run all tests"
  puts "  rake test_unit         # Run unit tests only"
  puts "  rake test_integration  # Run integration tests only"
  puts "  rake test_verbose      # Run tests with verbose output"
end
