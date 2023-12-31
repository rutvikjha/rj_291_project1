# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html
  if event['path'] == '/'
    #Execute get request
    if event['httpMethod'] == 'GET'
      begin
        headers = event['headers']
        auth = headers['Authorization']
        title = auth.split(" ")[0]
        token = auth.split(" ")[1]
        if title != "Bearer"
          #Bearer Header missing Do we need this?
          return response(body: {error: 'Forbidden'}, status: 403)
        end
        data = JWT.decode(token, ENV['JWT_SECRET'])
    
      #EXCEPTION HANDLING
      #Not valid token
      rescue JWT::ImmatureSignature => e
        return response(body: {error:'Unauthorized'}, status: 401)
      #Token is expired
      rescue JWT::ExpiredSignature => e
        return response(body: {error:'Unauthorized'}, status: 401)
      #Bearer header missing
      rescue JWT::DecodeError => e
        return response(body: {error: 'Forbidden'}, status: 403)
      #All other exceptions give 403
      rescue
        return response(body: {error: 'Forbidden'}, status: 403)
      else
        return response(body: data[0]["data"], status: 200)
      end
    else
      return response(body: {error: 'Method Not Allowed'}, status: 405)
    end
  elsif event['path'] == '/token'
    #execute post request
    if event['httpMethod'] == 'POST'
      begin
        #request content type is not 'application/json'
        if !event["headers"]["Content-Type"].nil? and event["headers"]["Content-Type"] != "application/json"
          return response(body: {error: 'Unsupported Media Type'}, status: 415)
        end
        out = JSON.parse(event["body"])
      rescue
        #Failure to parse JSON
        return response(body: {error: 'Unprocessable Entity'}, status: 422)
      else
        source = {data: out, exp: Time.now.to_i + 5, nbf: Time.now.to_i + 2}
        token = JWT.encode(source, ENV['JWT_SECRET'], 'HS256')
        return response(body: {"token" => token}, status: 201)
      end
    else
      return response(body: {error: 'Method Not Allowed'}, status: 405)
    end
  else
    return response(body: {error: 'Page Not Found'}, status: 404)
  end
end

def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  ENV['JWT_SECRET'] = 'NOTASECRET'

  # Call /token
  PP.pp main(context: {}, event: {
               'body' => '{"name": "bboe"}',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/token'
             })

  # Generate a token
  payload = {
    data: { user_id: 128 },
    exp: Time.now.to_i + 1,
    nbf: Time.now.to_i
  }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  # Call /
  PP.pp main(context: {}, event: {
               'headers' => { 'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/'
             })
end
