# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/icinga"
require "logstash/codecs/plain"
require "logstash/event"

describe LogStash::Outputs::Icinga do
  let(:host) { "example.com" }
  let(:user) { "icinga" }
  let(:password) { "supersecret" }

  let(:sample_event) { LogStash::Event.new }
  let(:output) { LogStash::Outputs::Icinga.new("host" => host, "user" => user, "password" => password) }


  before do
    output.register
  end

  it "should register without errors" do
    plugin = LogStash::Plugin.lookup("output", "icinga").new("host" => host, "user" => user, "password" => password)
    expect { plugin.register }.to_not raise_error
  end

  describe "receive message" do
    subject { output.receive(sample_event) }

    it "returns a string" do
      expect(subject).to eq("Event received")
    end
  end
end
