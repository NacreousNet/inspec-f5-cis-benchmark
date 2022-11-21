# CIS F5 Networks Benchmark - InSpec Profile

#F5 CIS 1.0 Benchmark Inspec Profile

#This repository is based on the F5 Center for Internet Security (CIS) version 1.0 Benchmark Inspec Profile.

#Required Disclaimer
#---------------------
#This is not an officially supported F5 product. This code is intended to help users assess their security posture on the F5 BIG-IP against the CIS Benchmark.
#This code is not certified by CIS.

# Description : This profile implements the [CIS F5 Networks 1.0.0 Benchmark](https://www.cisecurity.org/benchmark/).


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




#--------------------------------------------------------------------------------------------------------------------
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
#---------------------------------------------------------------------------------------------------------------------

cis_version = input('cis_version')
cis_url = input('cis_url')
control_id = '5'
control_abbrev = 'system'

control "cis-f5-#{control_id}.1-#{control_abbrev}" do

 title "[#{control_abbrev.upcase}] Ensure redundant NTP servers are configured appropriately (Manual)"

  desc  "To ensure redundant NTP servers are configured.\n\nRationale: "
  #Impact:
    #Failing to connect to an NTP server results on incorrect time zone and date which impacts several functions on BIG-IP systems.
    # It is recommended to have dual NTP servers configured to avoid single point of failure .
  
  
    #impact 0.0
  impact high

  tag cis_scored: true
  tag cis_level: 1
  tag cis_f5: "#{control_id.to_s}.1"
  tag cis_version: cis_version.to_s
  tag nist: ['AC-2']
  tag cis_version : v8
  tag cis_ig : ['IG 2','IG 3']


  describe "cis-f5-benchmark-#{control_id}.1" do
    skip 'Not implemented'
  end

end


control "cis-f5-#{control_id}.2-#{control_abbrev}" do

 title "[#{control_abbrev.upcase}] Ensure to exclude inode information from ETags HTTP Header (Manual)"

  desc  "To prevent the disclosure of inode information when accessing Configuration utility (GUI).\n\nRationale: "
  
  #Impact:
  #=========
  #When connecting to the Configuration utility, responses from the Apache server contain an
  # Etag HTTP header that includes the file's inode information.(CVE-2003-1418).  
 
  #impact 0.0
  impact high

  tag cis_scored: true
  tag cis_level: 1
  tag cis_f5: "#{control_id.to_s}.2"
  tag cis_version: cis_version.to_s
  tag nist: ['AC-2']
  tag cis_version : v8
  tag cis_ig : ['IG 1','IG 2','IG 3']


  describe "cis-f5-benchmark-#{control_id}.2" do
    skip 'Not implemented'

# Audit
# 1-Log in to tmsh by entering the following command: tmsh
# 2-check current HTTPD settings : list /sys httpd

   #Remediation
    # 1-Log in to tmsh by entering the following command: tmsh
   # 2-To specify the format to be used for the Etag header, enter the following command:
   # 3-modify /sys httpd include "FileETag MTime Size" Save the configuration change by entering the following command:
   # 4-save /sys config
   # 5-To restart the httpd service, enter the following command: restart /sys service httpd


   #
#Reference: 1. https://support.f5.com/csp/article/K14206
#CIS Controls v8 : 4.2 Establish and Maintain a Secure Configuration Process for Network Infrastructure
# Establish and maintain a secure configuration process for network devices.
# Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard. 


  end

end

control "cis-f5-#{control_id}.3-#{control_abbrev}" do

 title "[#{control_abbrev.upcase}] Ensure port lockdown for self IP is set (Manual)"

  desc  "to secure the BIG-IP system from unwanted connection attempts on self-IP.\n\nRationale: "
  
  #Impact:
  #=========
  #Default settings allow BIG-IP to listen on several ports on which some are not needed .
  # Attackers may initiate attacks against the system self IPs on these ports .
  # To reduce the risk , only needed ports should be enabled on self IPs.
  
  #impact 0.0
  impact high

  tag cis_scored: true
  tag cis_level: 1
  tag cis_f5: "#{control_id.to_s}.3"
  tag cis_version: cis_version.to_s
  tag nist: ['AC-2']
  tag cis_version : v8
  tag cis_ig : ['IG 2','IG 3']


  describe "cis-f5-benchmark-#{control_id}.3" do
    skip 'Not implemented'

# Audit
# 1-Log in to tmsh by typing the following command: tmsh
# 2-Type the command : tmsh list net self-allow
# 3-The output shows what protocols allowed for self-ip

   #Remediation
   #1-Log in to the Configuration utility.
   # 2-Go to Network > Self IPs.
   # 3-Select the relevant self IP address.
   # 4-If the specified interface does not need to listen to incoming connections ( Example BGP ,BDF ..etc) , set "Port Lockdown" to "Allow None"
   # 5-If the specified interface need to listen for incoming connections , set "Port Lockdown" to "Allow Custom". Then in the "Custom List" add needed ports only.


   #
#Reference: 1. https://support.f5.com/csp/article/K17333
#CIS Controls v8 : 12.3 Securely Manage Network Infrastructure
# Securely manage network infrastructure. Example implementations include version-controlled-infrastructure-as-code,
# and the use of secure network protocols, such as SSH and HTTPS.

  end

end


control "cis-f5-#{control_id}.4-#{control_abbrev}" do

 title "[#{control_abbrev.upcase}] Ensure to disable unused services in BIG-IP configuration (Manual)"

  desc  "To disable unused BIG-IP system daemons.\n\nRationale: "
  
  #Impact:
  #=========
  #Many systems break-ins are a result of people taking advantage of security holes or problems with these programs.
  # The more services that are running on your system, the more opportunities there are for others to use them,
  # break into or take control of your system through them. 
  
  #impact 0.0
  impact high

  tag cis_scored: true
  tag cis_level: 1
  tag cis_f5: "#{control_id.to_s}.4"
  tag cis_version: cis_version.to_s
  tag nist: ['AC-2']
  tag cis_version : v8
  tag cis_ig : ['IG 2','IG 3']


  describe "cis-f5-benchmark-#{control_id}.4" do
    skip 'Not implemented'

# Audit
# 1- Log in to the Configuration utility.
# 2- Go to System > Services > Services List
# 3-Check running service

#Remediation
# 1- Log in to the Configuration utility.
# 2- Go to System > Services > Services List
# 3-Select the unnecessary services you want to disable , then click "stop"
# 4-Click OK

#
#Reference: 1. https://support.f5.com/csp/article/K05645522
#CIS Controls v8 : 12.2 Establish and Maintain a Secure Network Architecture
# Establish and maintain a secure network architecture. A secure network architecture must address segmentation,
# least privilege, and availability, at a minimum.

  end

end



