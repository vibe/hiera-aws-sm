Puppet::Functions.create_function(:hiera_aws_sm) do
  begin; require 'json'; rescue LoadError; raise Puppet::DataBinding::LookupError, '[hiera-aws-sm] Must install json gem'; end
  begin; require 'aws-sdk-core'; rescue LoadError; raise Puppet::DataBinding::LookupError, '[hiera-aws-sm] Must install aws-sdk-core gem'; end
  begin; require 'aws-sdk-secretsmanager'; rescue LoadError; raise Puppet::DataBinding::LookupError, '[hiera-aws-sm] Must install aws-sdk-secretsmanager gem'; end

  dispatch :lookup_key do
    param 'Variant[String, Numeric]', :key
    param 'Hash', :options
    param 'Puppet::LookupContext', :context
  end

  def lookup_key(key, options, context)
    if confine_keys = options['confine_to_keys']
      unless confine_keys.any? { |r| Regexp.new(r).match(key) }
        context.explain { "[hiera-aws-sm] Skipping backend as #{key} doesn't match confine_to_keys" }
        context.not_found
      end
    end

    keys_to_try = if prefixes = options['prefixes']
                    delimiter = options['delimiter'] || '/'
                    prefixes.map { |p| [p.chomp(delimiter), key].join(delimiter) }
                  else
                    [key]
                  end

    keys_to_try.each do |secret_key|
      result = get_secret(secret_key, options, context)
      return result unless result.nil?
    end

    context.not_found
  end

  def get_secret(key, options, context)
    client_opts = { region: options['region'] }.compact

    roles = options['assume_role_chain']

    if roles.is_a?(Array) && !roles.empty?
      begin; require 'aws-sdk-sts'; rescue LoadError; raise Puppet::DataBinding::LookupError, '[hiera-aws-sm] Must install aws-sdk-sts gem'; end

      credentials = roles.reduce(nil) do |creds, role|
        session_name = role['role_session_name'] || 'puppet-hiera-sm'
        Aws::AssumeRoleCredentials.new(credentials: creds, role_arn: role['role_arn'], role_session_name: session_name)
      end
      client_opts[:credentials] = credentials
    end

    context.explain { "[hiera-aws-sm] Looking up #{key}" }
    secretsmanager = Aws::SecretsManager::Client.new(client_opts)

    begin
      response = secretsmanager.get_secret_value(secret_id: key)
      return context.cache_and_return(JSON.parse(response.secret_string))
    rescue JSON::ParserError
      return context.cache_and_return(response.secret_string)
    rescue Aws::SecretsManager::Errors::ResourceNotFoundException
      return nil
    rescue Aws::SecretsManager::Errors::ServiceError => e
      raise Puppet::DataBinding::LookupError, "[hiera-aws-sm] Failed to lookup #{key} due to: #{e.message}"
    end
  end
end