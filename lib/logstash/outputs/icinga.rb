# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"

# An icinga output that does nothing.
class LogStash::Outputs::Icinga < LogStash::Outputs::Base
  config_name "icinga"

  public
  def register
  end # def register

  public
  def receive(event)
    return "Event received"
  end # def event
end # class LogStash::Outputs::Icinga
