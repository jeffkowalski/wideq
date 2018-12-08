require 'wideq/version'

require 'rest-client'
require 'json'
require 'securerandom'
require 'base64'
require 'addressable/uri'
require 'addressable/template'

$logger = Logger.new STDOUT if $logger.nil?

module WIDEQ
  GATEWAY_URL      = 'https://kic.lgthinq.com:46030/api/common/gatewayUriList'.freeze
  APP_KEY          = 'wideq'.freeze
  SECURITY_KEY     = 'nuts_securitykey'.freeze
  DATA_ROOT        = 'lgedmRoot'.freeze
  COUNTRY          = 'US'.freeze
  LANGUAGE         = 'en-US'.freeze
  SVC_CODE         = 'SVC202'.freeze
  CLIENT_ID        = 'LGAO221A02'.freeze
  OAUTH_SECRET_KEY = 'c053c2a6ddeb7ad97cb0eed0dcb31cf8'.freeze
  OAUTH_CLIENT_KEY = 'LGAO221A02'.freeze
  DATE_FORMAT      = '%a, %d %b %Y %H:%M:%S +0000'.freeze

  DEVICE_TYPE = {
    REFRIGERATOR: 101,
    KIMCHI_REFRIGERATOR: 102,
    WATER_PURIFIER: 103,
    WASHER: 201,
    DRYER: 202,
    STYLER: 203,
    DISHWASHER: 204,
    OVEN: 301,
    MICROWAVE: 302,
    COOKTOP: 303,
    HOOD: 304,
    AC: 401, # Includes heat pumps, etc., possibly all HVAC devices.
    AIR_PURIFIER: 402,
    DEHUMIDIFIER: 403,
    ROBOT_KING: 501, # Robotic vacuum cleaner?
    ARCH: 1001,
    MISSG: 3001,
    SENSOR: 3002,
    SOLAR_SENSOR: 3102,
    IOT_LIGHTING: 3003,
    IOT_MOTION_SENSOR: 3004,
    IOT_SMART_PLUG: 3005,
    IOT_DUST_SENSOR: 3006,
    EMS_AIR_STATION: 4001,
    AIR_SENSOR: 4003
  }.freeze

  class APIError < StandardError
    def message
      'An error reported by the API.'
    end
  end

  class TokenError < APIError
    def message
      'An authentication token was rejected.'
    end

    def initialize(code)
      @code = code
      super
    end
  end

  class NotLoggedInError < APIError
    def message
      'The session is not valid or expired.'
    end
  end

  class DeviceNotConnectedError < APIError
    def message
      'The device is not connected.'
    end
  end

  class MonitorError < APIError
    def message
      "Monitoring a device (#{device_id}) failed with code #{code}, possibly because the monitoring session failed and needs to be restarted."
    end

    def initialize(device_id, code)
      @device_id = device_id
      @code = code
      super()
    end
  end

  ##
  # Look up a list using a key from an object.
  #
  # If `obj[key]` is a list, return it unchanged. If is something else,
  # return a single-element list containing it. If the key does not
  # exist, return an empty list.
  def self.get_list(obj, key)
    val = obj[key]

    return val if val.nil? || val.is_a?(Array)

    [val]
  end

  ##
  # Make an HTTP request in the format used by the API servers.
  #
  # In this format, the request POST data sent as JSON under a special
  # key; authentication sent in headers. Return the JSON data extracted
  # from the response.
  #
  # The `access_token` and `session_id` are required for most normal,
  # authenticated requests. They are not required, for example, to load
  # the gateway server data or to start a session.
  def self.lgedm_post(url, data: nil, access_token: nil, session_id: nil)
    headers = {
      x_thinq_application_key: APP_KEY,
      x_thinq_security_key: SECURITY_KEY,
      accept: 'application/json',
      content_type: 'application/json'
    }
    headers[:x_thinq_token]      = access_token unless access_token.nil?
    headers[:x_thinq_jsessionId] = session_id unless session_id.nil?
    payload = { "#{DATA_ROOT}": data }.to_json

    RestClient::Request.new(method: :post,
                            url: url.to_str,
                            payload: payload,
                            headers: headers).execute do |response, _request, _result|
      case response.code
      when 200
        out = JSON.parse(response)[DATA_ROOT]
        $logger.debug out
        if out.key? 'returnCd'
          case out['returnCd']
          when '0000'
            out
          when '0102'
            raise NotLoggedInError
          when '0106'
            raise DeviceNotConnectedError
          when 9003
            raise NotLoggedInError, 'session creation failed'
          else
            raise APIError, "#{out['returnCd']} #{out['returnMsg']}"
          end
        else
          out
        end
      else
        raise "Invalid response #{response.to_str} received."
      end
    end
  end

  ##
  # Load information about the hosts to use for API interaction.
  def self.gateway_info
    lgedm_post(GATEWAY_URL, data: { countryCode: COUNTRY, langCode: LANGUAGE })
  end

  def self.gen_uuid
    SecureRandom.uuid
  end

  ##
  # Get the base64-encoded SHA-1 HMAC digest of a string, as used in
  # OAauth2 request signatures.
  #
  # Both the `secret` and `message` are given as text strings. We use
  # their UTF-8 equivalents.
  def self.oauth2_signature(message, secret)
    digest = OpenSSL::Digest.new 'sha1'
    key    = secret.encode Encoding::UTF_8
    data   = message.encode Encoding::UTF_8

    hmac = OpenSSL::HMAC.digest digest, key, data
    signature = Base64.encode64 hmac
    signature.chomp
  end

  ##
  # Construct the URL for users to log in (in a browser) to start an
  # authenticated session.
  def self.oauth_url(auth_base)
    url = Addressable::Template.new("#{auth_base}/login/sign_in{?query*}")
    url.expand('query' => {
                 'country' => COUNTRY,
                 'language' => LANGUAGE,
                 'svcCode' => SVC_CODE,
                 'authSvr' => 'oauth2',
                 'client_id' => CLIENT_ID,
                 'division' => 'ha',
                 'grant_type' => 'password'
               })
  end

  ##
  # Parse the URL to which an OAuth login redirected to obtain two
  # tokens: an access token for API credentials, and a refresh token for
  # getting updated access tokens.
  def self.parse_oauth_callback(url)
    uri = Addressable::URI.parse url
    [uri.query_values['access_token'], uri.query_values['refresh_token']]
  end

  ##
  # Use an access token to log into the API and obtain a session and
  # return information about the session.
  def self.login(api_root, access_token)
    url = api_root
    url.chop! if url[-1] == '/'
    url += '/member/login'
    data = {
      countryCode: COUNTRY,
      langCode: LANGUAGE,
      loginType: 'EMP',
      token: access_token
    }
    lgedm_post url, data: data
  end

  ##
  # Get a new access_token using a refresh_token.
  #
  # May raise a `TokenError`.
  def self.refresh_auth(oauth_root, refresh_token)
    token_url = oauth_root
    token_url.chop! if token_url[-1] == '/'
    token_url += '/oauth2/token'

    data = "grant_type=refresh_token&refresh_token=#{refresh_token}"

    # The timestamp for labeling OAuth requests can be obtained
    # through a request to the date/time endpoint:
    # https://us.lgeapi.com/datetime
    # But we can also just generate a timestamp.
    timestamp = Time.now.utc.strftime(DATE_FORMAT)

    # The signature for the requests is on a string consisting of two parts:
    #   (1) a fake request URL containing the refresh token, and
    #   (2) the timestamp
    req_url = '/oauth2/token?' + data
    sig = oauth2_signature "#{req_url}\n#{timestamp}", OAUTH_SECRET_KEY

    headers = {
      lgemp_x_app_key: OAUTH_CLIENT_KEY,
      lgemp_x_signature: sig,
      lgemp_x_date: timestamp,
      accept: 'application/json',
      content_type: 'application/x-www-form-urlencoded'
    }

    $logger.debug "requesting refresh auth\ntoken_url: #{token_url}\nreq_url: #{req_url}\nheaders: #{headers}\ndata: #{data}"
    RestClient::Request.new(method: :post,
                            url: token_url,
                            payload: data,
                            headers: headers).execute do |response, _request, _result|
      case response.code
      when 200
        res_data = JSON.parse(response)
        $logger.debug "Result: #{res_data}"
        raise TokenError, response.code if res_data['status'] != 1

        return res_data['access_token']
      else
        $logger.debug response
        raise TokenError, response.code
      end
    end
  end

  class Gateway
    attr_reader :auth_base, :api_root, :oauth_root
    def initialize(auth_base, api_root, oauth_root)
      @auth_base  = auth_base
      @api_root   = api_root
      @oauth_root = oauth_root
    end

    def self.discover
      gw = WIDEQ.gateway_info
      Gateway.new gw['empUri'], gw['thinqUri'], gw['oauthUri']
    end

    def oauth_url
      WIDEQ.oauth_url @auth_base
    end
  end

  class Auth
    attr_reader :gateway, :access_token, :refresh_token
    def initialize(gateway, access_token, refresh_token)
      @gateway       = gateway
      @access_token  = access_token
      @refresh_token = refresh_token
    end

    ##
    # Create an authentication using an OAuth callback URL.
    def self.from_url(gateway, url)
      access_token, refresh_token = WIDEQ.parse_oauth_callback url
      Auth.new gateway, access_token, refresh_token
    end

    ##
    # Start an API session for the logged-in user. Return the
    # Session object and a list of the user's devices.
    def start_session
      session_info = WIDEQ.login @gateway.api_root, @access_token
      session_id = session_info['jsessionId']
      [Session.new(self, session_id), WIDEQ.get_list(session_info, 'item')]
    end

    ##
    # Refresh the authentication, returning a new Auth object.
    def refresh
      new_access_token = WIDEQ.refresh_auth @gateway.oauth_root, @refresh_token
      Auth.new(@gateway, new_access_token, @refresh_token)
    end
  end

  class Session
    attr_reader :session_id
    def initialize(auth, session_id)
      @auth       = auth
      @session_id = session_id
    end

    ##
    # Make a POST request to the API server.
    #
    # This is like `lgedm_post`, but it pulls the context for the
    # request from an active Session.
    def post(path, data = nil)
      url = @auth.gateway.api_root
      url.chop if url[-1] == '/'
      url += '/' + path
      WIDEQ.lgedm_post(url, data: data, access_token: @auth.access_token, session_id: @session_id)
    end

    ## Get a list of devices associated with the user's account.
    # Return a list of dicts with information about the devices.
    def get_devices
      WIDEQ.get_list(post('device/deviceList'), 'item')
    end

    ##
    # Begin monitoring a device's status.
    #
    # Return a "work ID" that can be used to retrieve the result of
    # monitoring.
    def monitor_start(device_id)
      res = post('rti/rtiMon',
                 cmd: 'Mon',
                 cmdOpt: 'Start',
                 deviceId: device_id,
                 workId: WIDEQ.gen_uuid)
      res['workId']
    end

    ##
    # Get the result of a monitoring task.
    #
    # `work_id` is a string ID retrieved from `monitor_start`. Return
    # a status result, which is a bytestring, or None if the
    # monitoring is not yet ready.
    #
    # May raise a `MonitorError`, in which case the right course of
    # action is probably to restart the monitoring task.
    def monitor_poll(device_id, work_id)
      work_list = [{ deviceId: device_id, workId: work_id }]
      res = post('rti/rtiResult', workList: work_list)['workList']

      # Check for errors.
      $logger.debug res
      $logger.debug res.keys
      code = res.fetch('returnCode', nil) # returnCode can be missing.
      raise MonitorError.new(device_id, code) if code != '0000'
      # The return data may or may not be present, depending on the
      # monitoring task status.

      # The main response payload is base64-encoded binary data in
      # the `returnData` field. This sometimes contains JSON data
      # and sometimes other binary data.
      return Base64.decode64(res['returnData']) if res.key? 'returnData'

      nil
    end

    ##
    # Stop monitoring a device.
    def monitor_stop(device_id, work_id)
      post('rti/rtiMon',
           cmd: 'Mon',
           cmdOpt: 'Stop',
           deviceId: device_id,
           workId: work_id)
    end

    ##
    # Control a device's settings.
    #
    # `values` is a key/value map containing the settings to update.
    def set_device_controls(device_id, values)
      post('rti/rtiControl',
           cmd: 'Control',
           cmdOpt: 'Set',
           value: values,
           deviceId: device_id,
           workId: WIDEQ.gen_uuid,
           data: '')
    end

    ##
    # Get a device configuration option.
    # The `category` string should probably either be "Config" or
    # "Control"; the right choice appears to depend on the key.
    def get_device_config(device_id, key, category = 'Config')
      res = post('rti/rtiControl',
                 cmd: category,
                 cmdOpt: 'Get',
                 value: key,
                 deviceId: device_id,
                 workId: WIDEQ.gen_uuid,
                 data: '')
      res['returnData']
    end
  end

  ##
  # A monitoring task for a device.
  #
  # This task is robust to some API-level failures. If the monitoring
  # task expires, it attempts to start a new one automatically. This
  # makes one `Monitor` object suitable for long-term monitoring.
  class Monitor
    def initialize(session, device_id)
      @session   = session
      @device_id = device_id
    end

    def start
      @work_id = @session.monitor_start @device_id
    end

    def stop
      @session.monitor_stop @device_id, @work_id
    end

    ##
    # Get the current status data (a bytestring) or None if the
    # device is not yet ready.
    def poll
      @session.monitor_poll @device_id, @work_id
    rescue MonitorError
      # Try to restart the task.
      stop
      start
      nil
    end

    ##
    # Decode a bytestring that encodes JSON status data.
    def self.decode_json(data)
      json.loads(data.decode('utf8'))
    end

    ##
    # For devices where status is reported via JSON data, get the
    # decoded status result (or None if status is not available).
    def poll_json
      data = poll
      data.nil? ? nil : decode_json(data)
    end
  end

  ##
  # A higher-level API wrapper that provides a session more easily
  # and allows serialization of state.
  class Client
    attr_accessor :_auth

    def initialize(gateway = nil, auth = nil, session = nil)
      # The three steps required to get access to call the API.
      @_gateway = gateway
      @_auth    = auth
      @_session = session

      # The last list of devices we got from the server.
      # This is the raw JSON list data describing the devices.
      @_devices = nil

      # Cached model info data. This is a mapping from URLs to JSON
      # responses.
      @_model_info = {}
    end

    def gateway
      @_gateway = Gateway.discover if @_gateway.nil?
      @_gateway
    end

    def auth
      assert False, 'unauthenticated' if @_auth.nil?
      @_auth
    end

    def session
      (@_session, @_devices) = auth.start_session if @_session.nil?
      @_session
    end

    ##
    # DeviceInfo objects describing the user's devices.
    def devices
      @_devices = session.get_devices if @_devices.nil?
      @_devices.map { |d| DeviceInfo.new d }
    end

    ##
    # For a DeviceInfo object, get a ModelInfo object describing
    # the model's capabilities.
    def model_info(device)
      url = device.model_info_url
      @_model_info[url] = device.load_model_info unless @_model_info.key? url
      ModelInfo.new @_model_info[url]
    end

    ##
    # Look up a DeviceInfo object by device ID.
    # Return None if the device does not exist.
    def get_device(device_id)
      devices.each do |device|
        return device if device.id == device_id
      end
      nil
    end

    ##
    # Load a client from serialized state.
    def self.load(state)
      gateway = nil
      if state.key? 'gateway'
        data = state['gateway']
        gateway = Gateway.new data[:auth_base], data[:api_root], data[:oauth_root]
      end

      auth = nil
      if state.key? 'auth'
        data = state['auth']
        auth = Auth.new gateway, data[:access_token], data[:refresh_token]
      end

      session = nil
      session = Session.new auth, state['session'] if state.key? 'session'

      client = Client.new gateway, auth, session

      # if state.has_key? 'model_info'
      #   client._model_info = state['model_info']
      # end

      client
    end

    ##
    # Serialize the client state.
    def dump
      out = {
        'model_info': @_model_info
      }

      if @_gateway
        out['gateway'] = {
          auth_base: @_gateway.auth_base,
          api_root: @_gateway.api_root,
          oauth_root: @_gateway.oauth_root
        }
      end

      if @_auth
        out['auth'] = {
          access_token: @_auth.access_token,
          refresh_token: @_auth.refresh_token
        }
      end

      out['session'] = @_session.session_id if @_session

      out
    end

    def refresh
      @_auth = auth.refresh
      (@_session, @_devices) = auth.start_session
    end

    ##
    # Construct a client using just a refresh token.
    # This allows simpler state storage (e.g., for human-written
    # configuration) but it is a little less efficient because we need
    # to reload the gateway servers and restart the session.
    def self.from_token(refresh_token)
      client = Client.new
      client._auth = Auth client.gateway, nil, refresh_token
      client.refresh
      client
    end
  end

  ##
  # Details about a user's device.
  # This is populated from a JSON dictionary provided by the API.
  class DeviceInfo
    def initialize(data)
      @data = data
    end

    def model_id
      @data['modelNm']
    end

    def id
      @data['deviceId']
    end

    def model_info_url
      @data['modelJsonUrl']
    end

    def name
      @data['alias']
    end

    ##
    # The kind of device
    def type
      DEVICE_TYPE.key(@data['deviceType'])
    end

    ##
    # Load JSON data describing the model's capabilities.
    def load_model_info
      JSON.parse(RestClient.get(model_info_url))
    end
  end

  EnumValue      = Struct.new :options
  RangeValue     = Struct.new :min, :max
  BitValue       = Struct.new :options
  ReferenceValue = Struct.new :reference

  ##
  # A description of a device model's capabilities.
  class ModelInfo
    def initialize(data)
      @data = data
    end

    def value_type(name)
      @data['Value'][name]['type'] if @data['Value'].key? name
    end

    ##
    # Look up information about a value.
    # Return either an `EnumValue` or a `RangeValue`.
    def value(name)
      d = @data['Value'][name]
      raise KeyError if d.nil?

      type = d['type']
    rescue KeyError
      $logger.warn "can't find type for #{name}"
    else
      if type.casecmp? 'enum'
        $logger.debug "#{name} is an enum"
        EnumValue.new d['option']
      elsif type.casecmp? 'range'
        $logger.debug "#{name} is a range"
        RangeValue.new d['option']['min'], d['option']['max'] # , d['option']['step']
      elsif type.casecmp? 'bit'
        $logger.debug "#{name} is a bit"
        bit_values = {}
        d['option'].each do |bit|
          bit_values[bit['startbit']] = {
            value: bit['value'],
            length: bit['length']
          }
        end
        BitValue.new bit_values
      elsif type.casecmp? 'reference'
        $logger.debug "#{name} is a reference"
        ref = d['option'][0]
        ReferenceValue.new @data[ref]
      elsif type.casecmp? 'boolean'
        $logger.debug "#{name} is a boolean"
        EnumValue.new(0 => 'False', 1 => 'True')
      else
        $logger.warn "unsupported value type #{d['type']} for value #{name}"
      end
    end

    ##
    # Get the default value, if it exists, for a given value.
    def default(name)
      @data['Value'][name]['default']
    end

    ##
    # Look up the encoded value for a friendly enum name.
    def enum_value(key, name)
      return value unless value_type(key)

      options = value(key).options
      options_inv = options.invert # FIXME, use value lookup instead
      options_inv[name]
    end

    ##
    # Look up the friendly enum name for an encoded value.
    def enum_name(key, value)
      options = value(key).options
      options[value]
    end

    ##
    # Look up the value of a RangeValue.  Not very useful other than for comprehension
    def range_name(key)
      key
    end

    ##
    # Look up the friendly name for an encoded bit value
    def bit_name(key, bit_index, val)
      return val unless value_type(key)

      options = value(key).options
      return val unless value_type(options[bit_index]['value'])

      enum_options = value(options[bit_index]['value']).options
      enum_options[val]
    end

    ##
    # Look up the friendly name for an encoded reference value
    def reference_name(key, val)
      return val unless value_type(key)

      reference = value(key).reference
      return '-' unless reference.key? val

      comment = reference[val]['_comment']
      return comment if comment

      reference[val]['label']
    end

    ##
    # Check that type of monitoring is BINARY(BYTE).
    def binary_monitor_data
      @data['Monitoring']['type'] == 'BINARY(BYTE)'
    end

    ##
    # Decode binary encoded status data.
    def decode_monitor_binary(data)
      decoded = {}
      @data['Monitoring']['protocol'].each do |item|
        key = item['value']
        value = 0
        data[item['startByte']..(item['startByte'] + item['length'] - 1)].unpack('C*').each do |v|
          value = (value << 8) + v
        end
        decoded[key] = value
      end
      decoded
    end

    ##
    # Decode a bytestring that encodes JSON status data.
    def decode_monitor_json(data)
      JSON.parse(data.decode('utf8'))
    end

    ##
    # Decode status data.
    def decode_monitor(data)
      if binary_monitor_data
        decode_monitor_binary(data)
      else
        decode_monitor_json(data)
      end
    end
  end

  ##
  # A higher-level interface to a specific device.
  #
  # Unlike `DeviceInfo`, which just stores data *about* a device,
  # `Device` objects refer to their client and can perform operations
  # regarding the device.
  class Device
    ##
    # Create a wrapper for a `DeviceInfo` object associated with a `Client`.
    def initialize(client, device)
      @client = client
      @device = device
      @model  = client.model_info(device)
    end

    ##
    # Set a device's control for `key` to `value`.
    def _set_control(_key, value)
      @client.session.set_device_controls @device.id, key: value
    end

    ##
    # Look up a device's configuration for a given value.
    # The response is parsed as base64-encoded JSON.
    def _get_config(key)
      data = @client.session.get_device_config @device.id, key
      JSON.parse(base64.b64decode(data).decode('utf8'))
    end

    ##
    # Look up a device's control value.
    def _get_control(key)
      data = client.session.get_device_config @device.id, key, 'Control'

      # The response comes in a funky key/value format: "(key:value)".
      _ignore, value = data[1..-1].split(':')
      value
    end
  end
end
