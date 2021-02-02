# frozen_string_literal: true

require 'omniauth-oauth2'
require 'net/https'
require 'jwt'

module OmniAuth
  module Strategies
    class Apple < OmniAuth::Strategies::OAuth2
      option :name, 'apple'

      option :client_options,
             site: 'https://appleid.apple.com',
             authorize_url: '/auth/authorize',
             token_url: '/auth/token'
      option :authorize_params,
             response_mode: 'form_post',
             scope: 'email name'
      option :authorized_client_ids, []

      uid { id_info['sub'] }

      info do
        prune!(
          sub: id_info['sub'],
          email: email,
          first_name: first_name,
          last_name: last_name,
          name: (first_name || last_name) ? [first_name, last_name].join(' ') : email,
        )
      end

      extra do
        id_token = request.params['id_token'] || access_token.try(:params).try(:dig, 'id_token')
        if id_token.nil? then return end
        prune!(raw_info: {id_info: id_info, user_info: user_info, id_token: id_token})
      end

      def client
        ::OAuth2::Client.new(client_id, client_secret, deep_symbolize(options.client_options))
      end

      def authorize_params
        super.merge(nonce: new_nonce)
      end

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end

      private

      def new_nonce
        session['omniauth.nonce'] = SecureRandom.urlsafe_base64(16)
      end

      def stored_nonce
        session.delete('omniauth.nonce')
      end

      def id_info
        @id_info ||= if request.params.try(:key?, 'id_token') || access_token.try(:params).try(:key?, 'id_token')
                       id_token = request.params['id_token'] || access_token.params['id_token']
		                   jwt_data = id_token.split(".")
		                   payload = JWT::JSON.parse(JWT::Base64.url_decode(jwt_data[1]))
                       payload
                     end
      end
      def fetch_jwks
        uri = URI.parse('https://appleid.apple.com/auth/keys')
        response = Net::HTTP.get_response(uri)
        JSON.parse(response.body, symbolize_names: true)
      end

      def verify_nonce!(payload)
        return unless payload['nonce_supported']

        return if payload['nonce'] && payload['nonce'] == stored_nonce

        fail!(:nonce_mismatch, CallbackError.new(:nonce_mismatch, 'nonce mismatch'))
      end

      def client_id
        @client_id ||= if id_info.nil?
                         options.client_id
                       else
                         id_info['aud'] if options.authorized_client_ids.include? id_info['aud']
                       end
      end

      def user_info
        user = request.params['user']
        return {} if user.nil?

        @user_info ||= JSON.parse(user)
      end

      def email
        id_info['email']
      end

      def first_name
        user_info.dig('name', 'firstName')
      end

      def last_name
        user_info.dig('name', 'lastName')
      end

      def prune!(hash)
        hash.delete_if do |_, v|
          prune!(v) if v.is_a?(Hash)
          v.nil? || (v.respond_to?(:empty?) && v.empty?)
        end
      end

      def client_secret
        payload = {
          iss: options.team_id,
          aud: 'https://appleid.apple.com',
          sub: client_id,
          iat: Time.now.to_i,
          exp: Time.now.to_i + 60
        }
        headers = { kid: options.key_id }

        ::JWT.encode(payload, private_key, 'ES256', headers)
      end

      def private_key
        ::OpenSSL::PKey::EC.new(options.pem)
      end
    end
  end
end
