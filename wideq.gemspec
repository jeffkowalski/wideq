# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'wideq/version'

Gem::Specification.new do |spec|
  spec.name          = 'wideq'
  spec.version       = Wideq::VERSION
  spec.authors       = ['Jeff Kowalski']
  spec.email         = ['jeff.kowalski+wideq@gmail.com']

  spec.summary       = 'Reverse-engineered client for the LG SmartThinQ API'
  spec.description   = 'Based on a python library authored by Adrian Sampson, https://github.com/sampsyo/wideq'
  spec.homepage      = 'https://github.com/jeffkowalski/wideq'
  spec.license       = 'MIT'

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_dependency 'addressable', '~> 2.8'
  spec.add_dependency 'base64', '~> 0.2'
  spec.add_dependency 'json', '~> 2.6'
  spec.add_dependency 'rest-client', '~> 2.1'

  spec.add_development_dependency 'bundler', '~> 2.0'
  spec.add_development_dependency 'rake', '~> 13.0'
  spec.add_development_dependency 'rspec', '~> 3.12'

  spec.required_ruby_version = '>= 3.2.2'
end
