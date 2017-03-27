# encoding: utf-8
require 'logstash/outputs/base'
require 'logstash/namespace'
require 'logstash/json'
require 'net/http'
require 'uri'

# An icinga output that does nothing.
class LogStash::Outputs::Icinga < LogStash::Outputs::Base

  concurrency :single

  config_name 'icinga'

  # Icinga 2 API hostname or IP address
  config :host, :validate => :string, :required => true

  # Port number
  config :port, :validate => :number, :default => 5665

  # API user
  config :user, :validate => :string, :required => true

  # Password of API user
  config :password, :validate => :password, :required => true

  # SSL verification
  config :ssl_verify, :validate => :boolean, :default => true

  # This is the action the output should perform.
  # Multiple actions are available:
  # * process-check-result
  # * send-custom-notification
  # * acknowledge-problem
  # * remove-acknowledgement
  # * add-comment
  # * remove-comment
  # * schedule-downtime
  # * remove-downtime
  config :action, :validate => ['process-check-result', 'send-custom-notification', 'acknowledge-problem', 'acknowledge-problem', 'add-comment', 'remove-comment', 'schedule-downtime', 'remove-downtime'], :required => true

  # Set the configuration depending on the action.
  # Each action has different configuration parameters.
  config :action_config, :validate => :hash, :required => true

  # The host the action applies to
  config :icinga_host, :validate => :string, :required => true

  # The service the action applies to.
  config :icinga_service, :validate => :string

  ACTION_CONFIG_FIELDS = {
      'process-check-result' => {
          'exit_status' => { 'required' => true },
          'plugin_output' => { 'required' => true },
          'performance_data' => {},
          'check_command' => {},
          'check_source' => {}
      },
      'send-custom-notification' => {
          'author' => { 'required' => true },
          'comment' => { 'required' => true },
          'force' => {}
      },
      'acknowledge-problem' => {
          'author' => { 'required' => true },
          'comment' => { 'required' => true },
          'expiry' => {},
          'sticky' => {},
          'notify' => {}
      },
      'remove-acknowledgement' => {},
      'add-comment' => {
          'author' => { 'required' => true },
          'comment' => { 'required' => true }
      },
      'remove-comment' => {},
      'schedule-downtime' => {
          'author' => {},
          'comment' => {},
          'start_time' => {},
          'end_time' => {},
          'duration' => {},
          'fixed' => {},
          'trigger_name' => {},
          'child_options' => {}
      },
      'remove-downtime' => {}
  }

  public
  def register
    @url = "https://#{@host}/v1/actions/#{@action}"
    @uri = URI.parse(@url)

    @http = Net::HTTP.new(@host, @port)
    @http.use_ssl = true
    @ssl_verify ? ssl_verify_mode = OpenSSL::SSL::VERIFY_PEER : ssl_verify_mode = OpenSSL::SSL::VERIFY_NONE
    @http.verify_mode = ssl_verify_mode

    validate_action_config
  end # def register

  public
  def receive(event)
    icinga_host = event.sprintf(@icinga_host)
    icinga_service = event.sprintf(@icinga_service)

    # TODO: check if service is set, otherwise use ?host= parameter
    params = { :service => "#{icinga_host}!#{icinga_service}" }
    @uri.query = URI.encode_www_form(params)

    request_body = Hash.new
    @action_config.each do |key, value|
      request_body[key] = event.sprintf(value)
    end # each action_config

    request = Net::HTTP::Post.new(@uri.request_uri)
    request.initialize_http_header({'Accept' => 'application/json'})
    request.basic_auth(@user, @password.value)
    request.body = LogStash::Json.dump(request_body)
    @logger.debug("Request path: #{request.path}")
    @logger.debug("Request body: #{request.body}")

    # TODO: capture failures in response
    response = @http.request(request)
    @logger.debug("Response: #{response.body}")
  end # def event

  def validate_action_config
    ACTION_CONFIG_FIELDS[@action].each do |field, settings|
      if settings['required'] && !@action_config.key?(field)
        logger.error("Field '#{field}' is required for action '#{@action}'")
      end
    end

    @action_config.each_key do |field|
      if !ACTION_CONFIG_FIELDS[@action].key?(field)
        logger.warn("Field '#{field}' is not available for action '#{action}'")
      end
    end
  end # def validate_action_config
end # class LogStash::Outputs::Icinga
