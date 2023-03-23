module Keycloak

  class Middleware
    def initialize(app)
      @app = app
    end

    def call(env)
      method = env["REQUEST_METHOD"]
      path = env["PATH_INFO"]
      uri = env["REQUEST_URI"]

      if service.need_authentication?(method, path, env)
        assign_realm_id(uri, env)
        Rails.logger.info "Selected REALM #{self.realm_id}"

        logger.debug("Start authentication for #{method} : #{path}")
        token         = service.read_token(uri, env)
        decoded_token = service.decode_and_verify(token)
        authentication_succeeded(env, decoded_token)
      else
        logger.debug("Skip authentication for #{method} : #{path}")
        @app.call(env)
      end
    rescue TokenError => e
      authentication_failed(e.message)
    end

    def authentication_failed(message)
      logger.info(message)
      [401, {"Content-Type" => "application/json"}, [ { error: message }.to_json]]
    end

    def authentication_succeeded(env, decoded_token)
      Helper.assign_current_user_id(env, decoded_token)
      Helper.assign_current_authorized_party(env, decoded_token)
      Helper.assign_current_user_email(env, decoded_token)
      Helper.assign_current_user_locale(env, decoded_token)
      Helper.assign_current_user_custom_attributes(env, decoded_token, config.custom_attributes)
      Helper.assign_realm_roles(env, decoded_token)
      Helper.assign_resource_roles(env, decoded_token)
      Helper.assign_keycloak_token(env, decoded_token)
      @app.call(env)
    end

    def assign_realm_id(uri, env)
      self.realm_id = extract_realm_from_token(uri, env)
    end

    attr_accessor :realm_id

    def service
      Keycloak.service(realm_id)
    end

    def logger
      Keycloak.logger
    end

    def config
      Keycloak.config(realm_id)
    end

    private
    def extract_realm_from_token(uri, env)
      token = service.read_token(uri, env)

      return nil if token.blank?

      decoded_token = JWT.decode(token, nil, false)&.first
      url = URI.parse(decoded_token['iss'])

      return nil unless url.host.to_s == URI.parse(config.server_url).host.to_s

      url.path.gsub('/realms/', '')
    end
  end
end
