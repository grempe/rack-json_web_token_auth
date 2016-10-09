require 'bundler/gem_tasks'
require 'rspec/core/rake_task'
require 'rubocop/rake_task'
require 'wwtd/tasks'

desc 'Run RSpec'
RSpec::Core::RakeTask.new do |t|
  t.verbose = true
end

task default: :spec

RuboCop::RakeTask.new
