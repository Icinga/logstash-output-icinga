# encoding: utf-8
require 'logstash/outputs/base'
require 'logstash/namespace'
require 'logstash/json'
require 'net/http'
require 'uri'

#
# This plugin runs actions on an Icinga server by calling its API. The Icinga API is available since version 2.4.
# It replaces the formerly used command pipe by providing a similiar interface with filter capabilities. Actions are
# used in order to process check results, manage downtimes, tell Icinga to send notifications and so on.
#
# This plugin handles a defined set of actions. A list of all Icinga actions is avaiable in the
# https://docs.icinga.com/icinga2/latest/doc/module/icinga2/chapter/icinga2-api#icinga2-api-actions[Icinga Docs].
#
# Examples:
#
# . Process a check result based on syslog severity
#
# [source,ruby]
#     filter {
#       if [syslog_severity] == "error" {
#         mutate {
#           replace => { "exit_status" => "2" }
#         }
#       }
#     }
#     output {
#       icinga {
#         host           => 'demo.icinga.com'
#         user           => 'icinga'
#         password       => 'supersecret'
#         action         => 'process-check-result'
#         action_config  => {
#           exit_status   => "%{exit_status}"
#           plugin_output => "%{message}"
#         }
#         icinga_host    => "%{hostname}"
#         icinga_service => "dummy"
#       }
#     }
#
# . Set a downtime of 2 hours, starting from now
#
# [source,ruby]
#     filter {
#       ruby { code => "event.set('start_time', Time.now.to_i)" }
#       ruby { code => "event.set('end_time', Time.now.to_i + 7200)" }
#     }
#     output {
#       icinga {
#         host           => 'demo'
#         user           => 'root'
#         password       => 'icinga'
#         ssl_verify     => false
#         action         => 'schedule-downtime'
#         action_config  => {
#           author     => "logstash"
#           comment    => "Downtime set by Logstash Output"
#           start_time => "%{start_time}"
#           end_time   => "%{end_time}"
#         }
#         icinga_host    => '%{hostname}'
#         icinga_service => 'dummy'
#       }
#
class LogStash::Outputs::Icinga < LogStash::Outputs::Base

  concurrency :single

  config_name 'icinga'

  # The hostname(s) of your Icinga server. If the hosts list is an array, Logstash will send the action to the first
  # entry in the list. If it disconnects, the same request will be processed to the next host. An action is send to each
  # host in the list, until one is accepts it. If all hosts are unavailable, the action is discarded. Ports can be
  # specified on any hostname, which will override the global port config.
  #
  # For example:
  # [source,ruby]
  #     "127.0.0.1"
  #     ["127.0.0.1", "127.0.0.2"]
  #     ["127.0.0.1:5665", "127.0.0.2"]
  config :host, :validate => :array, :default => ["127.0.0.1"]

  # Global port configuration. Can be overriten on any hostname.
  config :port, :validate => :number, :default => 5665

  # The Icinga API user. This user must exist on your Icinga server. It is an object of the type 'ApiUser'. Make sure
  # this user has sufficient permissions to run the actions you configure. Learn about it in the
  # https://docs.icinga.com/icinga2/latest/doc/module/icinga2/chapter/object-types#objecttype-apiuser[Icinga documentation about ApiUser].
  config :user, :validate => :string, :required => true

  # Password of the Icinga API user
  config :password, :validate => :password, :required => true

  # Connecting to the Icinga API is only available through SSL encryption. Set this setting to `false` to disable SSL
  # verification.
  config :ssl_verify, :validate => :boolean, :default => true

  # All actions must target an `icinga_host` or an `icinga_service`.
  # [cols="<,<",]
  # |=======================================================================
  # |Action |Description
  # | <<process-check-result,process-check-result>> |Process a check result.
  # | <<send-custom-notification,send-custom-notification>> |Send a custom notification.
  # | <<add-comment,add-comment>> |Add a comment from an author.
  # | <<remove-comment,remove-comment>> |Remove all comments created by a certain author.
  # | <<schedule-downtime,schedule-downtime>> |Schedule a downtime for a host or service.
  # | <<remove-downtime,remove-downtime>> |Remove all downtimes created by a certain author.
  # |=======================================================================
  config :action, :validate => ['process-check-result', 'send-custom-notification', 'add-comment', 'remove-comment', 'schedule-downtime', 'remove-downtime'], :required => true

  # Each action has its own parameters. Values of settings inside of `action_config` may include existing fields.
  #
  # [source,ruby]
  #     icinga {
  #       [...]
  #       action        => "add-comment"
  #       action_config => {
  #         author  => "%{somefield}_logstash"
  #         comment => "%{message}"
  #       }
  #     }
  #
  # ====== `process-check-result`
  # [cols="<,<,<",]
  # |=======================================================================
  # |Setting |Input type|Required
  # | `exit_status` |<<number,number>>, For services: 0=OK, 1=WARNING, 2=CRITICAL, 3=UNKNOWN, for hosts: 0=OK, 1=CRITICAL.|Yes
  # | `plugin_output` |<<string,string>>, The plugins main output. Does not contain the performance data.|Yes
  # | `performance_data` |<<array,array>>, The performance data.|No
  # | `check_command` |<<array,array>>, The first entry should be the check commands path, then one entry for each command line option followed by an entry for each of its argument.|No
  # | `check_source` |<<string,string>>, Usually the name of the `command_endpoint`|No
  # |=======================================================================
  #
  # ====== `send-custom-notification`
  # [cols="<,<,<",]
  # |=======================================================================
  # |Setting |Input type|Required
  # | `author` |<<string,string>>, Name of the author.|Yes
  # | `comment` |<<string,string>>, Comment text.|Yes
  # | `force` |<<boolean,boolean>>, Default: `false`. If `true`, the notification is sent regardless of downtimes or whether notifications are enabled or not.|No
  # |=======================================================================
  #
  # ====== `add-comment`
  # [cols="<,<,<",]
  # |=======================================================================
  # |Setting |Input type|Required
  # | `author` |<<string,string>>, Name of the author.|Yes
  # | `comment` |<<string,string>>, Comment text.|Yes
  # |=======================================================================
  #
  # ====== `remove-comment`
  # [cols="<,<,<",]
  # |=======================================================================
  # |Setting |Input type|Required
  # | `author` |<<string,string>>, Name of the author.|Yes
  # |=======================================================================
  #
  # ====== `schedule-downtime`
  # [cols="<,<,<",]
  # |=======================================================================
  # |Setting |Input type|Required
  # | `author` |<<string,string>>, Name of the author.|Yes
  # | `comment` |<<string,string>>, Comment text.|Yes
  # | `start_time` |<<timestamp (epoc),timestamp (epoc)>>, Timestamp marking the beginning of the downtime.|Yes
  # | `end_time` |<<timestamp (epoc),timestamp (epoc)>>, Timestamp marking the end of the downtime.|Yes
  # | `fixed` |<<boolean,boolean>>, Defaults to `true`. If `true`, the downtime is fixed otherwise flexible.|No
  # | `duration` |<<number,number>>, Duration of the downtime in seconds if fixed is set to `false`.|Required for flexible downtimes
  # | `trigger_name` |<<string,string>>, Sets the trigger for a triggered downtime.|No
  # | `child_options` |<<number,number>>, Schedule child downtimes. `0` does not do anything, `1` schedules child downtimes triggered by this downtime, `2` schedules non-triggered downtimes. Defaults to `0`.|No
  # |=======================================================================
  #
  # ====== `remove-downtime`
  # [cols="<,<,<",]
  # |=======================================================================
  # |Setting |Input type|Required
  # | `author` |<<string,string>>, Name of the author.|Yes
  # |=======================================================================
  #
  # Detailed information about each action are listed in the
  # https://docs.icinga.com/icinga2/latest/doc/module/icinga2/chapter/icinga2-api#icinga2-api-actions[Icinga Docs]
  config :action_config, :validate => :hash, :required => true

  # The Icinga `Host` object. This field may include existing fields.
  #
  # [source,ruby]
  #     icinga {
  #       [...]
  #       icinga_host => "%{hostname}"
  #     }
  config :icinga_host, :validate => :string, :required => true

  # The Icinga `Service` object. This field may include existing fields.
  #
  # [source,ruby]
  #     icinga {
  #       [...]
  #       icinga_host => "%{hostname}"
  #       icinga_service => "%{program}"
  #     }
  config :icinga_service, :validate => :string

  # If the host or service does not exist, it can be created automatically by settings this parameter to 'true'. A
  # service can only be created if its host already exists. This limitation is necessary because we cannot decide
  # automatically how to handle the host based on the desired action for the service. To bypass this behaviour, you
  # can use the 'icinga' output multiple times in a row, where you first create the host and then the service.
  config :create_object, :validate => :boolean, :default => false

  # You should make sure to have a special template for hosts and services created by logstash. Defining a 'check_command'
  # is mandatory when creating hosts or services. If your template does not handle this, you neet to set the 'check_command'
  # in 'object_attrs'. You can set more then one templates in an array, the default is set to 'logstash-service'.
  #
  # Examples for an icinga host template:
  #
  # [source,c]
  #  template Host "logstash-host" {
  #    enable_passive_checks = 1
  #    enable_active_checks = 0
  #    check_command = "dummy"
  #  }
  #
  # Example for an icinga service template:
  #
  # [source,c]
  #  template Service "logstash-service" {
  #    enable_passive_checks = 1
  #    enable_active_checks = 0
  #    check_command = "dummy"
  #  }
  config :object_templates, :validate => :array, :default => ['logstash-service']

  # A hash of attributes for the object. The values can be existing fields.
  # The default is set to "'vars.created_by' => 'logstash'"
  #
  # Example:
  #
  # [source,ruby]
  #  object_attrs => {
  #    'vars.os' => "%{operatingsystem}"
  #  }
  config :object_attrs, :validate => :hash, :default => {'vars.created_by' => 'logstash'}

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
      'add-comment' => {
          'author' => { 'required' => true },
          'comment' => { 'required' => true }
      },
      'remove-comment' => {
          'author' => { 'required' => true }
      },
      'schedule-downtime' => {
          'author' => { 'required' => true },
          'comment' => { 'required' => true},
          'start_time' => { 'required' => true},
          'end_time' => { 'required' => true },
          'duration' => {},
          'fixed' => {},
          'trigger_name' => {},
          'child_options' => {}
      },
      'remove-downtime' => {
          'author' => { 'required' => true }
      }
  }

  public
  def register
    validate_action_config
    @ssl_verify ? @ssl_verify_mode = OpenSSL::SSL::VERIFY_PEER : @ssl_verify_mode = OpenSSL::SSL::VERIFY_NONE
    @host_id = 0
  end # def register

  public
  def receive(event)

    @available_hosts = @host.count

    begin
      @httpclient ||= connect
      request_body = Hash.new
      icinga_host = event.sprintf(@icinga_host)
      icinga_service = event.sprintf(@icinga_service)

      @uri.path = "/v1/actions/#{@action}"

      # Depending on the action we take, set either a filter in the request body or set a host and/or service in the
      # url parameters.
      case @action
        when 'remove-downtime', 'remove-comment'
          action_type = @action.split('-').last
          request_body['type'] = action_type.capitalize
          if @icinga_service
            request_body['filter'] = "host.name == \"#{icinga_host}\" && service.name == \"#{icinga_service}\" && #{action_type}.author == \"#{@action_config['author']}\""
          else
            request_body['filter'] = "host.name == \"#{icinga_host}\" && #{action_type}.author == \"#{@action_config['author']}\""
          end
        else
          if @icinga_service
            @uri.query = URI.encode_www_form({:service => "#{icinga_host}!#{icinga_service}"})
          else
            @uri.query = URI.encode_www_form({:host => icinga_host})
          end

          @action_config.each do |key, value|
            request_body[key] = event.sprintf(value)
          end
      end

      request = Net::HTTP::Post.new(@uri.request_uri)
      request.initialize_http_header({'Accept' => 'application/json'})
      request.basic_auth(@user, @password.value)
      request.body = LogStash::Json.dump(request_body)

      response = @httpclient.request(request)
      raise StandardError if response.code != '200'

      response_body = LogStash::Json.load(response.body)
      response_body['results'].each do |result|
        logging_data = {
            :host => "#{@uri.host}:#{@uri.port}",
            :request_path => request.path,
            :request_body => request.body,
            :result_code => result['code'].to_i,
            :result_status => result['status']
        }

        if result['code'] == 200
          @logger.debug("Action '#{@action}' succeeded", logging_data)
        else
          @logger.warn("Action '#{@action}' failed", logging_data)
        end
      end.empty? and begin
        @logger.debug('Returned result was epty', :response_body => response.body)
      end

    rescue Timeout::Error => e
      @logger.warn( "Request failed",
                    :host => @uri.host, :port => @uri.port,
                    :path => request.path, :body => request.body,
                    :error => e )
      # If a host is not reachable, try the same request with the next host in the list. Try each host host only once per
      # request.
      if not (@available_hosts -= 1).zero?
        @httpclient = connect
        @logger.info("Retrying request with '#{@uri.host}:#{@uri.port}'")
        retry
      end

    rescue StandardError => e
      @logger.warn( "Request failed",
                     :host => @uri.host, :port => @uri.port,
                     :path => request.path, :body => request.body,
                     :response_code => response.code, :response_body => response.body,
                     :error => e )

      # If a object does not exist, create it and retry action
      if response.code == '404' and @create_object == true
        object = create_object(event)

        if object.code == '200'
          @logger.info("Retrying action on freshly created object", :action => @action)
          retry
        else
          @logger.warn("Failed to create object", :response_code => object.code, :response_body => object.body)
          next
        end
      end

    end
  end # def event

  private
  def validate_action_config
    ACTION_CONFIG_FIELDS[@action].each do |field, settings|
      if settings['required'] && !@action_config.key?(field)
        @logger.error("Setting '#{field}' is required for action '#{@action}'")
      end
    end

    @action_config.each_key do |field|
      if not ACTION_CONFIG_FIELDS[@action].key?(field)
        @logger.warn("Unknown setting '#{field}' for action '#{action}'")
      end
    end
  end # def validate_action_config

  def connect
    @current_host, @current_port = @host[@host_id].split(':')
    @host_id = @host_id + 1 >= @host.length ? 0 : @host_id + 1

    if not @current_port
      @current_port = @port
    end

    @uri = URI.parse("https://#{@current_host}:#{@current_port}")

    http = Net::HTTP.new(@uri.host, @uri.port)
    http.use_ssl = true
    http.verify_mode = @ssl_verify_mode
    http.open_timeout = 2
    http.read_timeout = 5
    http
  end # def http_connect

  def create_object(event)
    object_config = Hash.new
    object_config['templates'] = @object_templates
    object_config['attrs'] = Hash.new
    icinga_host = event.sprintf(@icinga_host)
    icinga_service = event.sprintf(@icinga_service)

    @object_attrs.each do |key, value|
      object_config['attrs'][key] = event.sprintf(value)
    end

    if @icinga_service
      @uri.path = '/v1/objects/services/' + URI.encode("#{icinga_host}!#{icinga_service}")
    else
      @uri.path = '/v1/objects/hosts/' + URI.encode(icinga_host)
    end

    @uri.query = URI.encode_www_form({:ignore_on_error => 1})

    request = Net::HTTP::Put.new(@uri.request_uri)
    request.initialize_http_header({'Accept' => 'application/json'})
    request.basic_auth(@user, @password.value)
    request.body = LogStash::Json.dump(object_config)

    @logger.info( "Creating Object",
                   :request_uri => @uri.request_uri,
                   :request_body => request.body,
                   :icinga_host => icinga_host, :icinga_service => icinga_service )

    response = @httpclient.request(request)
    response
  end # def create_object
end # class LogStash::Outputs::Icinga
