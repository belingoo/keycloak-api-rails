require "logger"
require "json/jwt"
require "uri"
require "date"
require "net/http"

require_relative "keycloak-api-rails/configuration"
require_relative "keycloak-api-rails/http_client"
require_relative "keycloak-api-rails/token_error"
require_relative "keycloak-api-rails/helper"
require_relative "keycloak-api-rails/public_key_resolver"
require_relative "keycloak-api-rails/public_key_cached_resolver"
require_relative "keycloak-api-rails/service"
require_relative "keycloak-api-rails/middleware"
require_relative "keycloak-api-rails/railtie" if defined?(Rails)

module Keycloak

  def self.configure
    yield @configuration ||= Keycloak::Configuration.new
  end

  def self.config(realm_id)
    if @configurations[realm_id].blank?
      new_config = @configuration.dup
      new_config.realm_id = realm_id
      @configurations[realm_id] = new_config
    end
    @configurations[realm_id]
  end

  def self.http_client(realm_id)
    @http_clients[realm_id] ||= Keycloak::HTTPClient.new(config(realm_id))
  end

  def self.public_key_resolver(realm_id)
    @public_key_resolvers ||= {}
    @public_key_resolvers[realm_id] ||= PublicKeyCachedResolver.from_configuration(
      http_client(realm_id),
      config(realm_id))
  end

  def self.service(realm_id)
    @services[realm_id] ||= Keycloak::Service.new(realm_id, public_key_resolver(realm_id))
  end

  def self.logger
    @configuration.logger
  end

  def self.init_variables
    @services = {}
    @configurations = {}
    @http_clients = {}
  end

  def self.load_configuration
    init_variables
    configure do |config|
      config.server_url                             = nil
      config.realm_id                               = nil
      config.logger                                 = ::Logger.new(STDOUT)
      config.skip_paths                             = {}
      config.token_expiration_tolerance_in_seconds  = 10
      config.public_key_cache_ttl                   = 86400
      config.custom_attributes                      = []
    end
  end

  load_configuration
end
