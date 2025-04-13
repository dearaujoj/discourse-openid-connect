# frozen_string_literal: true
require "base64"
require "openssl"

class OpenIDConnectAuthenticator < Auth::ManagedAuthenticator
  def name
    "oidc"
  end

  def can_revoke?
    SiteSetting.openid_connect_allow_association_change
  end

  def can_connect_existing_user?
    SiteSetting.openid_connect_allow_association_change
  end

  def enabled?
    SiteSetting.openid_connect_enabled
  end

  def validate_groups(auth)
    return true if SiteSetting.openid_connect_required_groups.blank?

    required_groups = SiteSetting.openid_connect_required_groups.split("|")
    groups_claim = SiteSetting.openid_connect_groups_claim
    
    log_groups_debug("Starting group validation for user")
    log_groups_debug("Required groups: #{required_groups.inspect}")
    
    user_groups = auth["extra"]["raw_info"][groups_claim]
    
    if user_groups.nil?
      log_groups_debug("No groups found in claim '#{groups_claim}'", error: true)
      return false
    end
    
    # Handle both array and string formats
    user_groups = user_groups.split(",") if user_groups.is_a?(String)
    user_groups = Array(user_groups)
    
    log_groups_debug("User groups (#{groups_claim}): #{user_groups.inspect}")
    
    matching_groups = required_groups & user_groups
    has_required_group = matching_groups.any?
    
    if has_required_group
      log_groups_debug("Access granted - user has required group(s): #{matching_groups.inspect}")
    else
      log_groups_debug("Access denied - user has none of the required groups", error: true)
    end
    
    has_required_group
  end

  def log_groups_debug(message, error: false)
    return unless SiteSetting.openid_connect_groups_debug_logging || error
    
    prefix = error ? "OIDC Groups [ERROR]" : "OIDC Groups [DEBUG]"
    Rails.logger.send(error ? :error : :info, "#{prefix}: #{message}")
  end

  def after_authenticate(auth)
    result = super

    if result.failed?
      oidc_log("Authentication failed: #{result.failed_reason}", error: true)
      return result
    end

    unless validate_groups(auth)
      result.failed = true
      result.failed_reason = I18n.t("login.not_in_required_group")
      log_groups_debug("Group validation failed for user", error: true)
    end

    result
  end

  def primary_email_verified?(auth)
    supplied_verified_boolean = auth["extra"]["raw_info"]["email_verified"]
    # If the payload includes the email_verified boolean, use it. Otherwise assume true
    if supplied_verified_boolean.nil?
      true
    else
      # Many providers violate the spec, and send this as a string rather than a boolean
      supplied_verified_boolean == true ||
        (supplied_verified_boolean.is_a?(String) && supplied_verified_boolean.downcase == "true")
    end
  end

  def always_update_user_email?
    SiteSetting.openid_connect_overrides_email
  end

  def match_by_email
    SiteSetting.openid_connect_match_by_email
  end

  def discovery_document
    document_url = SiteSetting.openid_connect_discovery_document.presence
    if !document_url
      oidc_log("No discovery document URL specified", error: true)
      return
    end

    from_cache = true
    result =
      Discourse
        .cache
        .fetch("openid-connect-discovery-#{document_url}", expires_in: 10.minutes) do
          from_cache = false
          oidc_log("Fetching discovery document from #{document_url}")
          connection =
            Faraday.new(request: { timeout: request_timeout_seconds }) do |c|
              c.use Faraday::Response::RaiseError
              c.adapter FinalDestination::FaradayAdapter
            end
          response = connection.get(document_url)
          oidc_log("Raw discovery document response:\n#{response.body}")
          JSON.parse(response.body)
        rescue Faraday::Error, JSON::ParserError => e
          oidc_log("Fetching discovery document raised error #{e.class} #{e.message}", error: true)
          nil
        end

    oidc_log("Discovery document loaded from cache") if from_cache
    oidc_log("Discovery document is\n\n#{result.to_yaml}")

    result
  end

  def oidc_log(message, error: false)
    if error
      Rails.logger.error("OIDC Log: #{message}")
    elsif SiteSetting.openid_connect_verbose_logging
      Rails.logger.warn("OIDC Log: #{message}")
    end
  end

  def register_middleware(omniauth)
    omniauth.provider :openid_connect,
                      name: :oidc,
                      error_handler:
                        lambda { |error, message|
                          handlers = SiteSetting.openid_connect_error_redirects.split("\n")
                          handlers.each do |row|
                            parts = row.split("|")
                            return parts[1] if message.include? parts[0]
                          end
                          nil
                        },
                      verbose_logger: lambda { |message| oidc_log(message) },
                      setup:
                        lambda { |env|
                          opts = env["omniauth.strategy"].options

                          token_params = {}
                          token_params[
                            :scope
                          ] = SiteSetting.openid_connect_token_scope if SiteSetting.openid_connect_token_scope.present?

                          opts.deep_merge!(
                            client_id: SiteSetting.openid_connect_client_id,
                            client_secret: SiteSetting.openid_connect_client_secret,
                            discovery_document: discovery_document,
                            scope: SiteSetting.openid_connect_authorize_scope,
                            token_params: token_params,
                            passthrough_authorize_options:
                              SiteSetting.openid_connect_authorize_parameters.split("|"),
                            claims: SiteSetting.openid_connect_claims,
                            pkce: SiteSetting.openid_connect_use_pkce,
                            pkce_options: {
                              code_verifier: -> { generate_code_verifier },
                              code_challenge: ->(code_verifier) do
                                generate_code_challenge(code_verifier)
                              end,
                              code_challenge_method: "S256",
                            },
                          )

                          opts[:client_options][:connection_opts] = {
                            request: {
                              timeout: request_timeout_seconds,
                            },
                          }

                          opts[:client_options][:connection_build] = lambda do |builder|
                            if SiteSetting.openid_connect_verbose_logging
                              builder.response :logger,
                                               Rails.logger,
                                               { bodies: true, formatter: OIDCFaradayFormatter }
                            end

                            builder.request :url_encoded # form-encode POST params
                            builder.adapter FinalDestination::FaradayAdapter # make requests with FinalDestination::HTTP
                          end
                        }
  end

  def generate_code_verifier
    Base64.urlsafe_encode64(OpenSSL::Random.random_bytes(32)).tr("=", "")
  end

  def generate_code_challenge(code_verifier)
    Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier)).tr("+/", "-_").tr("=", "")
  end

  def request_timeout_seconds
    GlobalSetting.openid_connect_request_timeout_seconds
  end
end
