# encoding: utf-8
require 'logstash/devutils/rspec/spec_helper'
require 'logstash/outputs/icinga'
require 'logstash/event'
require 'webmock/rspec'

describe LogStash::Outputs::Icinga do
  let(:host) { ['icinga.com:5665', 'example.net', 'example.com'] }
  let(:user) { 'icinga' }
  let(:password) { 'secret' }
  let(:action) { 'add-comment' }
  let(:action_config) { {'author' => 'rspec', 'comment' => 'test'} }
  let(:icinga_host) { 'srv-1' }
  let(:icinga_service) { 'dummy' }
  let(:options) {
    {
        'host' => host,
        'user' => user,
        'password' => password,
        'action' => action,
        'action_config' => action_config,
        'icinga_host' => icinga_host,
        'icinga_service' => icinga_service,
        'create_object' => true
    }
  }
  let(:event) { LogStash::Event.new({ 'message' => 'This is a dummy message.' }) }
  let(:request) { "https://#{host[0]}/v1/actions/#{action}?service=#{icinga_host}!#{icinga_service}" }
  let(:request_body) { "{\"author\":\"#{action_config['author']}\",\"comment\":\"#{action_config['comment']}\"}" }
  let(:response_body) { "{\"results\":[{\"code\":200.0,\"legacy_id\":34.0,\"name\":\"#{icinga_host}!#{icinga_service}!rspec-1494247033-25\",\"status\":\"Successfully added comment '#{icinga_host}!#{icinga_service}!rspec-1494247033-25' for object '#{icinga_host}!#{icinga_service}'.\"}]}" }
  let(:output) { LogStash::Outputs::Icinga.new(options) }
  let(:logger) { output.logger }

  before do
    output.register
  end

  after do
    WebMock.reset!
  end

  context 'with working configuration' do
    it 'should register without errors' do
      plugin = LogStash::Plugin.lookup('output', 'icinga').new(options)
      expect { plugin.register }.to_not raise_error
    end

    it 'should send the event to icinga' do
      stub_request(:post, request).
          with(:body => request_body,
               :basic_auth => [user, password],
               :headers => {'Accept'=>'application/json'}).
          to_return(
              :status => 200,
              :body => response_body,
              :headers => {})
      expect(logger).to receive(:debug).with("Action '#{action}' succeeded", instance_of(Hash))
      output.receive(event)
    end
  end

  context 'with broken connection' do
    it 'should retry with the next host' do
      stub_request(:post, request).
          with(:body => request_body,
               :basic_auth => [user, password],
               :headers => {'Accept'=>'application/json'}).
          to_raise(Timeout::Error)

      expect(logger).to receive(:warn).with("Request failed", instance_of(Hash))

      expect(logger).to receive(:info).with("Retrying request with '#{host[1]}:5665'")

      stub_request(:post, "https://#{host[1]}:5665/v1/actions/#{action}?service=#{icinga_host}!#{icinga_service}").
          with(:body => request_body,
               :basic_auth => [user, password],
               :headers => {'Accept'=>'application/json'}).
          to_return(
              :status => 200,
              :body => response_body,
              :headers => {})

      expect(logger).to receive(:debug).with("Action '#{action}' succeeded", instance_of(Hash))

      output.receive(event)
    end

    it 'should try each host only once per request' do
      stub_request(:post, request).
          with(:body => request_body,
               :basic_auth => [user, password],
               :headers => {'Accept'=>'application/json'}).
          to_raise(Timeout::Error)

      expect(logger).to receive(:warn).with("Request failed", instance_of(Hash))

      expect(logger).to receive(:info).with("Retrying request with '#{host[1]}:5665'")

      stub_request(:post, "https://#{host[1]}:5665/v1/actions/#{action}?service=#{icinga_host}!#{icinga_service}").
          with(:body => request_body,
               :basic_auth => [user, password],
               :headers => {'Accept'=>'application/json'}).
          to_raise(Timeout::Error)

      expect(logger).to receive(:warn).with("Request failed", instance_of(Hash))

      expect(logger).to receive(:info).with("Retrying request with '#{host[2]}:5665'")

      stub_request(:post, "https://#{host[2]}:5665/v1/actions/#{action}?service=#{icinga_host}!#{icinga_service}").
          with(:body => request_body,
               :basic_auth => [user, password],
               :headers => {'Accept'=>'application/json'}).
          to_raise(Timeout::Error)

      expect(logger).to receive(:warn).with("Request failed", instance_of(Hash))


      output.receive(event)
    end
  end

  context 'with invalid action_config' do
    it 'should inform about missing settings' do
      action_config = {'comment' => 'test'}
      options = {
          'host' => host,
          'user' => user,
          'password' => password,
          'action' => action,
          'action_config' => action_config,
          'icinga_host' => icinga_host,
          'icinga_service' => icinga_service
      }
      plugin = LogStash::Plugin.lookup('output', 'icinga').new(options)
      logger = output.logger
      expect(logger).to receive(:error).with("Setting 'author' is required for action '#{action}'")
      plugin.register
    end

    it 'should inform about unknown settings' do
      action_config = {'author' => 'rspec', 'comment' => 'test', 'mysetting' => 'blue'}
      options = {
          'host' => host,
          'user' => user,
          'password' => password,
          'action' => action,
          'action_config' => action_config,
          'icinga_host' => icinga_host,
          'icinga_service' => icinga_service
      }
      plugin = LogStash::Plugin.lookup('output', 'icinga').new(options)
      logger = output.logger
      expect(logger).to receive(:warn).with("Unknown setting 'mysetting' for action '#{action}'")
      plugin.register
    end
  end

  context 'with create_object => true' do
    it 'should create object and retry action' do
      stub_request(:post, request).
          with(:body => request_body,
               :basic_auth => [user, password],
               :headers => {'Accept'=>'application/json'}).
          to_return(body: 'Object not found', status: 404, :headers => {}).
          to_raise(StandardError)

      expect(logger).to receive(:warn).with("Request failed", instance_of(Hash))

      stub_request(:put, "https://#{host[0]}/v1/objects/services/#{icinga_host}!#{icinga_service}").
          with(:body => '{"templates":["logstash-service"],"attrs":{"vars.created_by":"logstash"}}',
               :basic_auth => [user, password],
               :headers => {'Accept'=>'application/json'}).
          to_return(:status => 200, :body => '', :headers => {})

      stub_request(:post, request).
          with(:body => request_body,
               :basic_auth => [user, password],
               :headers => {'Accept'=>'application/json'}).
          to_return(body: '', status: 200, :headers => {})

      output.receive(event)
    end
  end
end

