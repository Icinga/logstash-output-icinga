# encoding: utf-8
require 'logstash/outputs/base'
require 'logstash/namespace'
require 'json'
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
  config :action, :validate => :string, :required => true

  # Set the configuration depending on the action.
  # Each action has different configuration parameters.
  config :action_config, :validate => :hash, :required => true

  # The host the action applies to
  config :icinga_host, :validate => :string, :required => true

  # The service the action applies to.
  config :icinga_service, :validate => :string

  public
  def register
    @url = 'https://' + @host + '/v1/actions'
    @uri = URI.parse(@url)

    @client = Net::HTTP.new(@host, @port)
    @client.use_ssl = true
    @ssl_verify ? ssl_verify_mode = OpenSSL::SSL::VERIFY_PEER : ssl_verify_mode = OpenSSL::SSL::VERIFY_NONE
    @client.verify_mode = ssl_verify_mode
  end # def register

  public
  def receive(event)
    $stdout.write('Host: ' + @host + ' User: ' + @user + ' Password: ' + @password.to_s)

    response = @client.request(create_request(@action, @action_config, @icinga_host, @icinga_service))
    @logger.debug('Response', response.body)
  end # def event

  public
  def create_request(action, action_config, icinga_host, icinga_service)
    params = { :service => "#{icinga_host}!#{icinga_service}" }
    @uri.query = URI.encode_www_form(params)
    @uri.path = @uri.path + '/' + action

    request = Net::HTTP::Post.new(@uri.request_uri)
    request.initialize_http_header({'Accept' => 'application/json'})
    request.basic_auth(@user, @password.value)
    request.body = action_config.to_json

    $stdout.write("\n action config: " + action_config.to_json + "\n\n\n")

    request
  end # def create_request
end # class LogStash::Outputs::Icinga
