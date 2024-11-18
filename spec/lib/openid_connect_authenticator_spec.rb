# frozen_string_literal: true

require "rails_helper"
require_relative "../../lib/omniauth_open_id_connect"

describe OpenIDConnectAuthenticator do
  let(:authenticator) { described_class.new }
  fab!(:user)
  let(:hash) do
    OmniAuth::AuthHash.new(
      provider: "oidc",
      uid: "123456789",
      info: {
        name: "John Doe",
        email: user.email,
      },
      extra: {
        raw_info: {
          email: user.email,
          name: "John Doe",
        },
      },
    )
  end

  context "when email_verified is not supplied" do
    # Some IDPs do not supply this information
    # In this case we trust that they have verified the address
    it "matches the user" do
      result = authenticator.after_authenticate(hash)

      expect(result.user).to eq(user)
    end
  end

  context "when email_verified is true" do
    it "matches the user" do
      hash[:extra][:raw_info][:email_verified] = true
      result = authenticator.after_authenticate(hash)
      expect(result.user).to eq(user)
    end

    it "matches the user as a true string" do
      hash[:extra][:raw_info][:email_verified] = "true"
      result = authenticator.after_authenticate(hash)
      expect(result.user).to eq(user)
    end

    it "matches the user as a titlecase true string" do
      hash[:extra][:raw_info][:email_verified] = "True"
      result = authenticator.after_authenticate(hash)
      expect(result.user).to eq(user)
    end
  end

  context "when email_verified is false" do
    it "does not match the user" do
      hash[:extra][:raw_info][:email_verified] = false
      result = authenticator.after_authenticate(hash)
      expect(result.user).to eq(nil)
    end

    it "does not match the user as a false string" do
      hash[:extra][:raw_info][:email_verified] = "false"
      result = authenticator.after_authenticate(hash)
      expect(result.user).to eq(nil)
    end
  end

  context "when match_by_email is false" do
    it "does not match the user" do
      SiteSetting.openid_connect_match_by_email = false
      result = authenticator.after_authenticate(hash)
      expect(result.user).to eq(nil)
    end
  end

  describe "discovery document fetching" do
    let(:document_url) do
      SiteSetting.openid_connect_discovery_document =
        "https://id.example.com/.well-known/openid-configuration"
    end
    let(:document) do
      {
        issuer: "https://id.example.com/",
        authorization_endpoint: "https://id.example.com/authorize",
        token_endpoint: "https://id.example.com/token",
        userinfo_endpoint: "https://id.example.com/userinfo",
      }.to_json
    end
    after { Discourse.cache.delete("openid-connect-discovery-#{document_url}") }

    it "loads the document correctly" do
      stub_request(:get, document_url).to_return(body: document)
      expect(authenticator.discovery_document.keys).to contain_exactly(
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
      )
    end

    it "handles a non-200 response" do
      stub_request(:get, document_url).to_return(status: 404)
      expect(authenticator.discovery_document).to eq(nil)
    end

    it "handles a network error" do
      stub_request(:get, document_url).to_timeout
      expect(authenticator.discovery_document).to eq(nil)
    end

    it "handles invalid json" do
      stub_request(:get, document_url).to_return(body: "this is not the json you're looking for")
      expect(authenticator.discovery_document).to eq(nil)
    end

    it "caches a success response" do
      stub = stub_request(:get, document_url).to_return(body: document)
      expect(authenticator.discovery_document).not_to eq(nil)
      expect(authenticator.discovery_document).not_to eq(nil)
      expect(stub).to have_been_requested.once
    end

    it "caches a failed response" do
      stub = stub_request(:get, document_url).to_return(status: 404)
      expect(authenticator.discovery_document).to eq(nil)
      expect(authenticator.discovery_document).to eq(nil)
      expect(stub).to have_been_requested.once
    end
  end

  describe "group validation" do
    before do
      hash[:extra][:raw_info][:email_verified] = true
    end

    context "when no groups are required" do
      before do
        SiteSetting.openid_connect_required_groups = ""
      end

      it "allows authentication" do
        result = authenticator.after_authenticate(hash)
        expect(result.failed).to eq(false)
      end
    end

    context "when groups are required" do
      before do
        SiteSetting.openid_connect_required_groups = "admin|staff"
      end

      context "with array format groups" do
        it "allows authentication when user has required group" do
          hash[:extra][:raw_info][:groups] = ["staff", "users"]
          result = authenticator.after_authenticate(hash)
          expect(result.failed).to eq(false)
        end

        it "denies authentication when user doesn't have required group" do
          hash[:extra][:raw_info][:groups] = ["users", "customers"]
          result = authenticator.after_authenticate(hash)
          expect(result.failed).to eq(true)
          expect(result.failed_reason).to eq(I18n.t("login.not_in_required_group"))
        end
      end

      context "with string format groups" do
        it "allows authentication when user has required group" do
          hash[:extra][:raw_info][:groups] = "admin,users"
          result = authenticator.after_authenticate(hash)
          expect(result.failed).to eq(false)
        end

        it "denies authentication when user doesn't have required group" do
          hash[:extra][:raw_info][:groups] = "users,customers"
          result = authenticator.after_authenticate(hash)
          expect(result.failed).to eq(true)
          expect(result.failed_reason).to eq(I18n.t("login.not_in_required_group"))
        end
      end

      context "with custom groups claim" do
        before do
          SiteSetting.openid_connect_groups_claim = "roles"
        end

        it "uses the custom claim name" do
          hash[:extra][:raw_info][:roles] = ["admin"]
          result = authenticator.after_authenticate(hash)
          expect(result.failed).to eq(false)
        end
      end

      context "when groups claim is missing" do
        it "denies authentication" do
          result = authenticator.after_authenticate(hash)
          expect(result.failed).to eq(true)
          expect(result.failed_reason).to eq(I18n.t("login.not_in_required_group"))
        end
      end

      context "with debug logging" do
        before do
          SiteSetting.openid_connect_required_groups = "admin|staff"
          SiteSetting.openid_connect_groups_debug_logging = true
        end

        it "logs debug information when enabled" do
          hash[:extra][:raw_info][:groups] = ["staff", "users"]
          
          messages = []
          Rails.logger.stubs(:info).with { |message| messages << message }
          
          authenticator.after_authenticate(hash)
          
          expect(messages).to include(match(/OIDC Groups \[DEBUG\]: Starting group validation/))
          expect(messages).to include(match(/OIDC Groups \[DEBUG\]: Required groups/))
          expect(messages).to include(match(/OIDC Groups \[DEBUG\]: User groups/))
          expect(messages).to include(match(/OIDC Groups \[DEBUG\]: Access granted/))
        end

        it "logs error information for failed validation" do
          hash[:extra][:raw_info][:groups] = ["users"]
          
          messages = []
          Rails.logger.stubs(:error).with { |message| messages << message }
          
          authenticator.after_authenticate(hash)
          
          expect(messages).to include(match(/OIDC Groups \[ERROR\]: Access denied/))
          expect(messages).to include(match(/OIDC Groups \[ERROR\]: Group validation failed/))
        end

        it "always logs errors even when debug logging is disabled" do
          SiteSetting.openid_connect_groups_debug_logging = false
          hash[:extra][:raw_info][:groups] = ["users"]
          
          messages = []
          Rails.logger.stubs(:error).with { |message| messages << message }
          Rails.logger.stubs(:info).with { |message| messages << message }
          
          authenticator.after_authenticate(hash)
          
          error_messages = messages.select { |m| m.include?("[ERROR]") }
          debug_messages = messages.select { |m| m.include?("[DEBUG]") }
          
          expect(error_messages).not_to be_empty
          expect(debug_messages).to be_empty
        end
      end
    end
  end
end
