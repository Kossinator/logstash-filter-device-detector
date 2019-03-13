# encoding: utf-8
require "logstash/filters/base"
require "device_detector"

class LogStash::Filters::DeviceDetector < LogStash::Filters::Base

  config_name "device_detector"

  config :source, :validate => :string, :required => true

  config :target, :validate => :string, :required => true

  public
  def register

  end 

  public
  def filter(event)

    # Receive source
    useragent = event.get(@source)
    return if useragent.nil? || useragent.empty?

    # Parse user-agent via device-detector
    begin
      data = DeviceDetector.new(useragent)
    rescue StandardError => e
      @logger.error("Uknown error while parsing device data", :exception => e, :field => @source, :event => event)
      return
    end
    return unless data

    # Remove original source (if its also the target)
    event.remove(@source) if @target == @source

    # Set all fields
    event.set("#{@target}[name]", data.name) if data.name
    event.set("#{@target}[full_version]", data.full_version) if data.full_version
    event.set("#{@target}[os_name]", data.os_name) if data.os_name
    event.set("#{@target}[os_full_version]", data.os_full_version) if data.os_full_version
    event.set("#{@target}[device_name]", data.device_name) if data.device_name
    event.set("#{@target}[device_brand]", data.device_brand) if data.device_brand
    event.set("#{@target}[device_type]", data.device_type) if data.device_type
    event.set("#{@target}[bot_name]", data.bot_name) if data.bot_name

    filter_matched(event)
  end
end