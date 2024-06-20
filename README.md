# Wideq - A Ruby Gem for Interacting with LG SmartThinq Appliances

This is a Ruby port of the code and concepts found in [sampsyo's wideq Python module](https://github.com/sampsyo/wideq).

See also https://github.com/ollo69/ha-smartthinq-sensors/blob/master/custom_components/smartthinq_sensors/wideq/core_async.py
more modern Python lib is here: https://github.com/pifou25/wideq

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'wideq'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install wideq

## Usage

``` ruby
## An example that lists available appliances

require 'wideq'

##
# Interactively authenticate the user via a browser to get an OAuth session.
def authenticate(gateway)
  login_url = gateway.oauth_url
  puts 'Log in here:'
  puts login_url
  puts 'Then paste the URL where the browser is redirected:'
  callback_url = gets.chomp
  WIDEQ::Auth.from_url gateway, callback_url
end

##
# List the user's devices.
def ls(client)
  client.devices.each do |device|
    puts "#{device.id}: \"#{device.name}\" (type #{device.type}, id #{device.model_id})"
  end
end

STATE_FILE = 'wideq_state.json'.freeze

begin
  state = JSON.parse(File.read(STATE_FILE))
rescue StandardError
  state = {}
end

# puts WIDEQ::gateway_info

client = WIDEQ::Client.load(state)
# Log in, if we don't already have an authentication.
client._auth = authenticate client.gateway unless client._auth

begin
  ls client
rescue WIDEQ::NotLoggedInError
  client.refresh
end

# Save the updated state.
state = client.dump
File.open(STATE_FILE, 'w') { |file| file.write state.to_json }

# pp client
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/jeffkowalski/wideq.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
