require 'byebug'

class HomesController < ApplicationController
  protect_from_forgery with: :exception, except: [:index, :create]

  def index
    if session[:userid]
      @user_id = session[:userid]
      # byebug
    else
      request = OneLogin::RubySaml::Authrequest.new
      redirect_to(request.create(saml_settings), allow_other_host: true)
    end
  end

  def create
    response          = OneLogin::RubySaml::Response.new(params[:SAMLResponse])
    response.settings = saml_settings

    # We validate the SAML Response and check if the user already exists in the system
    if response.is_valid?
       # authorize_success, log the user
      #  byebug
       session[:userid] = response.nameid
       session[:attributes] = response.attributes
       redirect_to('/')
    else
      byebug
      # authorize_failure  # This method shows an error message
      # List of errors is available in response.errors array
    end
  end


  private

  def saml_settings
    meta_data_parser = OneLogin::RubySaml::IdpMetadataParser.new
    settings_hash = meta_data_parser.parse_remote_to_hash('https://dev-97367895.okta.com/app/exkd360qf2U40OADG5d7/sso/saml/metadata')

    settings = OneLogin::RubySaml::Settings.new

    settings.assertion_consumer_service_url = "http://localhost:3001/azure/saml_callback"
    settings.sp_entity_id                   = "okta_demo"
    settings.idp_sso_service_url            = settings_hash[:idp_sso_service_url]
    settings.idp_cert_fingerprint           = settings_hash[:idp_cert_fingerprint]
    # settings.idp_cert_fingerprint           = settings_hash[:idp_cert_fingerprint]
    # settings.name_identifier_format         = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    # Optional for most SAML IdPs
    # settings.authn_context = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

    # Optional. Describe according to IdP specification (if supported) which attributes the SP desires to receive in SAMLResponse.
    # settings.attributes_index = 5
    # Optional. Describe an attribute consuming service for support of additional attributes.
    # settings.attribute_consuming_service.configure do
    #   service_name "Service"
    #   service_index 5
    #   add_attribute :name => "Name", :name_format => "Name Format", :friendly_name => "Friendly Name"
    # end

    settings
  end
end