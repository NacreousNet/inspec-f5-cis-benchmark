# CIS F5 Networks Benchmark - InSpec Profile

# Description : This profile implements the [CIS F5 Networks 1.0.0 Benchmark](https://www.cisecurity.org/benchmark/).
# 
# CIS F5: Terms of Use: https://www.cisecurity.org/cis-securesuite/cis-securesuite-membership-terms-of-use/
# CIS F5: Acknowledgements
# This benchmark exemplifies the great things a community of users, vendors, and subject matter
# experts can accomplish through consensus collaboration. The CIS community thanks the entire 
# consensus team with special recognition to the following individuals who contributed greatly to 
# the creation of this guide:
#
#
# CIS F5: Author Omar Batis
#
# CIS F5: Contributor Darren Freidel
#


#
# Copyright:: 2022, Philip Hines
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Philip Hines

title '1.1 Passwords'

BIGIP_HOST              = input('bigip_address')
BIGIP_PORT              = input('bigip_port')
BIGIP_USER              = input('user')
BIGIP_PASSWORD          = input('password')
NAMESERVER              = input('nameserver')


control 'cis-f5-benchmark-1.1.1' do
  title 'Ensure default password of root is not allowed (Automated)'
  desc  "To assist users in changing default password for "root" account.\n\nRationale: Using Default passwords for 'root' access could cause a compromise to the overall system security."
  impact 0.0

  tag cis: 'f5:1.1.1'
  tag level: 1

      #Password Strength Policy — IA-5(1)
      #NIST SP 800-53-5 IA-5(1) Authenticator Management | Password-Based Authentication
      tag nist: ['IA-5(1)']

  describe 'cis-f5-benchmark-1.1.1' do
    skip 'Not implemented'
  end
end

control 'cis-f5-benchmark-1.1.2' do
  title 'Ensure default password of admin is not used (Automated)'
  desc  "To assist users in changing default password for 'admin' account\n\nRationale: Using Default passwords for 'admin' access could cause a compromise to the overall system security."
  impact 0.0

  tag cis: 'f5:1.1.2'
  tag level: 1

      #Password Strength Policy — IA-5(1)
     #NIST SP 800-53-5 IA-5(1)(a) Authenticator Management | Password-Based Authentication

      tag nist: ['IA-5(1)']

  describe 'cis-f5-benchmark-1.1.2' do
    skip 'Not implemented'
  end
end

control 'cis-f5-benchmark-1.1.3' do
    title 'Configure Secure Password Policy (Manual)'
    desc  "To assist users in maintaining strong passwords, ensure that passwords are changed at appropriate intervals and new passwords to be used\n\nRationale: Having a weak or non-existent password policy will allow users to use weak or easily cracked passwords."
    impact 0.0

#Impact:
# Without proper password management the users are more likely to select weak passwords or forget complex passwords.
# This can create security risks as these passwords make it easier for attackers to crack.
    impact High

  
    tag cis: 'f5:1.1.3'
    tag level: 1

    #Password Strength Policy — IA-5(1)
     #NIST SP 800-53-5 IA-5(1)(h) Authenticator Management | Password-Based Authentication    
    tag nist: ['IA-5(1)']
  
    describe json(content: http("https://#{BIGIP_HOST}:#{BIGIP_PORT}/mgmt/tm/sys/dns",
              auth: {user: BIGIP_USER, pass: BIGIP_PASSWORD},
              method: 'GET',
              ssl_verify: false).body) do
          its('nameServers') { should cmp NAMESERVER }
    end



    describe 'cis-f5-benchmark-1.1.3' do
      skip 'Not implemented'

# Configuring the password policy using tmsh
# 1. Log in to tmsh by typing the following command: tmsh:
# modify /auth password-policy
# The minimum requirements :
# - Secure Password Enforcement : Enabled
# - Minimum Password Length is 12
# - Required Lowercase is 1
# - Required Uppercase is 1
# - Required Numeric is 1 
# - Required Special Characters is 1
# - Maximum Duration (in Days): 180
# - Minimum Duration (in Days): 90
# - Expiration Warning ( in days):14
# - EnsurePassword Memory is 24
# - Ensure Maximum Login Failures is 3

    end
  end
  