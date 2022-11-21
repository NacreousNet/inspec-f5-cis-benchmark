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


# Copyright 2022 The inspec-f5-cis-benchmark Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cis_version = input('cis_version')
cis_url = input('cis_url')
control_id = '4'
control_abbrev = 'cli_interface_management'



control "cis-f5-#{control_id}.1-#{control_abbrev}" do
 # impact 'high'

 # title "[#{control_abbrev.upcase}] Ensure that corporate login credentials are used"

  #desc 'Use corporate login credentials instead of personal accounts, such as Gmail accounts.'
  #desc 'rationale', "It is recommended fully-managed corporate Google accounts be used for increased visibility, auditing, and controlling access to Cloud Platform resources. Email accounts based outside of the user's organization, such as personal accounts, should not be used for business purposes."

#  tag cis_scored: true
#  tag cis_level: 1
#  tag cis_f5: control_id.to_s
#  tag cis_version: cis_version.to_s
#  tag nist: ['AC-2']



#title '4 CLI Interface Management'

#control 'cis-f5-benchmark-4.1' do
 # title 'Ensure Prelogin \'Login Banner\' is set (Manual)'
 title "[#{control_abbrev.upcase}] Ensure Prelogin \'Login Banner\' is set (Manual)"

  desc  "\n\nRationale: "
  #impact 0.0
  impact high

#  tag cis: 'f5:4.1'
#  tag level: 1
  tag cis_scored: true
  tag cis_level: 1
  tag cis_f5: "#{control_id.to_s}.1"
  tag cis_version: cis_version.to_s
  tag nist: ['AC-2']

  describe 'cis-f5-benchmark-4.1' do
    skip 'Not implemented'

#Reference: 1. https://support.f5.com/csp/article/K71515276

  end

  describe command('grep -E -i \'(\\v|\\r|\\m|\\s|$(grep \'^ID=\' /etc/os-release | cut -d= -f2 | sed -e \'s/"//g\'))\' /etc/issue.net') do
    its('stdout') { should eq '' }
  end


end

control 'cis-f5-benchmark-4.2' do
  title 'Ensure \'Idle timeout\' is less than or equal to 10 minutes for SSH connections (Manual)'
  desc  "To set an idle timeout for SSH sessions.\n\nRationale: ."
  impact 0.0

  tag cis: 'f5:3.2'
  tag level: 1

  describe 'cis-f5-benchmark-3.2' do
    skip 'Not implemented'

#1-Log in to tmsh by typing the following command:
# tmsh
#2-To configure an automatic logout idle time (10 minutes) for SSH sessions, use the following command syntax:
# modify /sys sshd inactivity-timeout 600
#3-Save the change by typing the following command:
# save /sys config

#Reference: https://support.f5.com/csp/article/K9908
#CIS Controls v8 : 4.1 Establish and Maintain a Secure Configuration Process
# Establish and maintain a secure configuration process for enterprise assets (end-user devices, including portable and mobile,
# non-computing/IoT devices, and servers) and software (operating systems and applications).
# Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.

  end

  describe sshd_config do
    its('ClientAliveInterval') { should cmp <= 300 }
    its('ClientAliveCountMax') { should cmp <= 0 }
  end


end

control 'cis-f5-benchmark-4.3' do
    title 'Ensure \'Idle timeout\' is less than or equal to 10 minutes for tmsh sessions (Manual)'
    desc  "To set an idle timeout for tmsh sessions\n\nRationale: "
    impact 0.0
  
    tag cis: 'f5:4.3'
    tag level: 1
  
    describe 'cis-f5-benchmark-4.3' do
      skip 'Not implemented'

#1.Log in to tmsh by typing the following command:
# tmsh
# 2.To configure an automatic logout idle time for tmsh sessions, use the following command syntax:
# modify /cli global-settings idle-timeout 10
# 3.Save the change by typing the following command:
# save /sys config      
#
#Reference: https://support.f5.com/csp/article/K9908
#CIS Controls v8 : 4.1 Establish and Maintain a Secure Configuration Process
# Establish and maintain a secure configuration process for enterprise assets (end-user devices, including portable and mobile,
# non-computing/IoT devices, and servers) and software (operating systems and applications).
# Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.

end
  end
  
  control 'cis-f5-benchmark-4.4' do
    title 'Ensure \'Idle timeout\' is less than or equal to 10 minutes for serial console sessions (Manual)'
    desc  "To set an idle timeout for serial console sessions.\n\nRationale: "
    impact 0.0
  
    tag cis: 'f5:4.4'
    tag level: 1
  
    describe 'cis-f5-benchmark-4.4' do
      skip 'Not implemented'

#1.Log in to tmsh by typing the following command:
# tmsh
# 2.To configure an automatic logout idle time for serial console sessions, use the following command:
# modify /sys global-settings console-inactivity-timeout 600
# 3.Save the change by typing the following command:
# save /sys config      
#
#Reference: https://support.f5.com/csp/article/K9908
#CIS Controls v8 : 4.1 Establish and Maintain a Secure Configuration Process
# Establish and maintain a secure configuration process for enterprise assets (end-user devices, including portable and mobile,
# non-computing/IoT devices, and servers) and software (operating systems and applications).
# Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.

end
  end

  control 'cis-f5-benchmark-4.5' do
    title 'Ensure minimum SSH Encryption algorithm is set to aes128-cbc (Manual)'
    desc  "To set strong SSH Encryption algorithm.\n\nRationale: "
    impact 0.0
  
    tag cis: 'f5:4.5'
    tag level: 1
  
    describe 'cis-f5-benchmark-4.5' do
      skip 'Not implemented'

# 1-Log in to tmsh by typing the following command:tmsh
# 2-To modify the sshd configuration, type the following command to start the vi editor:edit /sys sshd all-properties
# 3-To change the list of ciphers, you can navigate to the line that starts with the include statement, and use the keyword Ciphers :
# include "Ciphers aes128-cbc,aes128-ctr,aes192-ctr,aes256-ctr,arcfour128,arcfour256,arcfour"   
#
#Reference: https://support.f5.com/csp/article/K80425458
#CIS Controls v8 : 4.1 Establish and Maintain a Secure Configuration Process
# Establish and maintain a secure configuration process for enterprise assets (end-user devices, including portable and mobile,
# non-computing/IoT devices, and servers) and software (operating systems and applications).
# Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.

end


describe sshd_config do
    its('Ciphers') { should_not be_nil }
  end

  weak_ciphers = [
    '3des-cbc',
    'aes128-cbc',
    'aes192-cbc',
    'aes256-cbc',
    'arcfour',
    'arcfour128',
    'arcfour256',
    'blowfish-cbc',
    'cast128-cbc',
    'rijndael-cbc@lysator.liu.se',
  ].freeze

  if sshd_config.Ciphers
    describe sshd_config.Ciphers.split(',').each do
      it { should_not be_in weak_ciphers }
    end





  end


  control 'cis-f5-benchmark-4.6' do
    title 'Ensure to set SSH MAC algorithm to hmac-sha2-256 (Manual)'
    desc  "To set strong Hashing algorithm.\n\nRationale: "
    impact 0.0
  
    tag cis: 'f5:4.6'
    tag level: 1
    tag cis_version : v8
    #tag cis_group : [IG 1,IG 2,IG 3]
  
    describe 'cis-f5-benchmark-4.6' do
      skip 'Not implemented'

# 1-Log in to tmsh by typing the following command:tmsh
# 2-To modify the sshd configuration, type the following command to start the vi editor:edit /sys sshd all-properties 
# 3-To change the list of ciphers, you can navigate to the line that starts with the include statement, and use the keyword MACs ,
# and adding the list of desired MACs to the 2-line include statement:
# include "Ciphers aes128-cbc,aes128-ctr,aes192-ctr,aes256-ctr,arcfour128,arcfour256,arcfour MACs hmac-sha2-256"
#
#Reference: https://support.f5.com/csp/article/K80425458
#CIS Controls v8 : 4.1 Establish and Maintain a Secure Configuration Process
# Establish and maintain a secure configuration process for enterprise assets (end-user devices, including portable and mobile,
# non-computing/IoT devices, and servers) and software (operating systems and applications).
# Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.

end


describe sshd_config do
    its('MACs') { should_not be_nil }
  end

  allowed_macs = [
    'hmac-sha2-512-etm@openssh.com',
    'hmac-sha2-256-etm@openssh.com',
    'hmac-sha2-512',
    'hmac-sha2-256',
  ].freeze

  sshd_config.MACs&.split(',')&.each do |m|
    describe m do
      it { should be_in allowed_macs }
    end


  end

  control 'cis-f5-benchmark-4.7' do
    title 'Ensure to set Strong SSH KEY Exchange algorithm (Manual)'
    desc  "To set strong Key Exchange algorithm.\n\nRationale: "
    impact 0.0
  
    tag cis: 'f5:4.7'
    tag level: 1
  
    describe 'cis-f5-benchmark-4.7' do
      skip 'Not implemented'


#
#Reference:
#CIS Controls v8 : 4.2 Establish and Maintain a Secure Configuration Process for Network Infrastructure
# Establish and maintain a secure configuration process for network devices.
# Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard. 

end

describe sshd_config do
    its('KexAlgorithms') { should_not be_nil }
  end

  allowed_kex_algorithms = [
    'curve25519-sha256',
    'curve25519-sha256@libssh.org',
    'ecdh-sha2-nistp256',
    'ecdh-sha2-nistp384',
    'ecdh-sha2-nistp521',
    'diffie-hellman-group-exchange-sha256',
    'diffie-hellman-group16-sha512',
    'diffie-hellman-group18-sha512',
    'diffie-hellman-group14-sha256',
  ].freeze

  sshd_config.KexAlgorithms&.split(',')&.each do |m|
    describe m do
      it { should be_in allowed_kex_algorithms }
    end
  end


  end

  control 'cis-f5-benchmark-4.8' do
    title 'Ensure access SSH to CLI interface is restricted to needed IP addresses only (Manual)'
    desc  "To limit ssh access to trusted IPs only\n\nRationale: "
    impact 0.0
  
    tag cis: 'f5:4.8'
    tag level: 1
  
    describe 'cis-f5-benchmark-4.8' do
      skip 'Not implemented'

#
#Reference: 
#CIS Controls v8 : 4.2 Establish and Maintain a Secure Configuration Process for Network Infrastructure
# Establish and maintain a secure configuration process for network devices.
# Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard. 


# https://support.f5.com/csp/article/K5380

end
  end
