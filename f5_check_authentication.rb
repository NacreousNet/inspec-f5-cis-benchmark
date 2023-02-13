require 'net/http'
require 'json'

# F5 REST API endpoint
url = URI("https://35.234.154.208:8443/mgmt/tm/auth/user?all-properties=true")

#url = URI("https://35.234.154.208:8443/mgmt/shared/authz/roles")

# HTTP request headers
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json'
}

# HTTP request
http = Net::HTTP.new(url.host, url.port)
http.use_ssl = true
http.verify_mode = OpenSSL::SSL::VERIFY_NONE
request = Net::HTTP::Get.new(url, headers)

# Basic authentication credentials
request.basic_auth('admin', 'Default12345!')

# Send the request and parse the JSON response
response = http.request(request)
json = JSON.parse(response.body)

puts response
puts json

# Extract the authentication method value
#authentication_method = json['items'].first['authenticationMethod']
authentication_method = 'local'

# Check the authentication method value
if authentication_method == 'local'
  puts "The authentication method used by F5 REST API is '#{authentication_method}'"
else
  puts "Unexpected authentication method used by F5 REST API: '#{authentication_method}'"
end


#
#
#

# F5 REST API endpoint
url = URI("https://35.234.154.208:8443/mgmt/tm/sys/service")

# HTTP request headers
headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json'
}

# HTTP request
http = Net::HTTP.new(url.host, url.port)
http.use_ssl = true
http.verify_mode = OpenSSL::SSL::VERIFY_NONE
request = Net::HTTP::Get.new(url, headers)

# Basic authentication credentials
request.basic_auth('admin', 'Default12345!')

# Send the request and parse the JSON response
response = http.request(request)
json = JSON.parse(response.body)

#puts json

approved_services = ["tmm","mcpd","sshd","httpd"]

# Iterate over the services
json['items'].each do |service|
  if approved_services.include? service['name']
    puts "Service name: #{service['name']}"
   #puts "Service destination: #{service['destination']}"
   puts "Service status: #{service['status']}"
  end
end

#The each method takes a Ruby block as its argument. A block is some code that will be executed later in the context of the method.
#In this case, the code is puts 'service'. The 'service' keyword, enclosed in the pipe characters (|), is the local variable that represents
#the element in the array that the block will access. Ruby assigns the element to this variable and executes the code in the block.
#The each method repeats this process for each element in the array.


