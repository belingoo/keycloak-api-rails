module Keycloak
  class Service

    def initialize(realm_id, key_resolver)
      config = Keycloak.config(realm_id)
      @key_resolver = key_resolver
      @skip_paths = config.skip_paths
      @opt_in = config.opt_in
      @logger = config.logger
      @token_expiration_tolerance_in_seconds = config.token_expiration_tolerance_in_seconds
      @dev_mode = config.dev_mode
    end

    def decode_and_verify(token)
      unless token.nil? || token&.empty?
        public_key    = @key_resolver.find_public_keys
        decoded_token = JSON::JWT.decode(token, public_key)

        if expired?(decoded_token) && (@dev_mode.nil? || @dev_mode == false)
          raise TokenError.expired(token)
        else
          decoded_token.verify!(public_key)
          decoded_token
        end
      else
        raise TokenError.no_token(token)
      end
    rescue JSON::JWT::VerificationFailed => e
      raise TokenError.verification_failed(token, e)
    rescue JSON::JWK::Set::KidNotFound => e
      raise TokenError.verification_failed(token, e)
    rescue JSON::JWT::InvalidFormat
      raise TokenError.invalid_format(token, e)
    end

    def read_token(uri, headers)
      Helper.read_token_from_query_string(uri) || Helper.read_token_from_headers(headers)
    end

    def need_middleware_authentication?(method, path, headers)
      !is_preflight?(method, headers) && (!@opt_in && !should_skip?(method, path))
    end

    private

    def should_skip?(method, path)
      method_symbol = method&.downcase&.to_sym
      skip_paths    = @skip_paths[method_symbol]
      !skip_paths.nil? && !skip_paths.empty? && !skip_paths.find_index { |skip_path| skip_path.match(path) }.nil?
    end

    def is_preflight?(method, headers)
      method_symbol = method&.downcase&.to_sym
      method_symbol == :options && !headers["HTTP_ACCESS_CONTROL_REQUEST_METHOD"].nil?
    end

    def expired?(token)
      token_expiration = Time.at(token["exp"]).to_datetime
      token_expiration < Time.now + @token_expiration_tolerance_in_seconds.seconds
    end
  end
end
