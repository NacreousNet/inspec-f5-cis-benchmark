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
control_id = '6'
control_abbrev = 'monitoring-and-alerting'

control "cis-f5-#{control_id}.1-#{control_abbrev}" do

 title "[#{control_abbrev.upcase}] Ensure that SNMP access is allowed to trusted agents IPs only (Manual)"

  desc  "To limit access to trusted SNMP agents only.\n\nRationale: "
  #Impact:
  #Failing on restricting access to SNMP may allow unauthorised systems to gain access to the network device.  
  
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

#Audit
#1-Login to Configuration utility
# 2- Go to System > SNMP > Agent > Configuration
# 3- Check "Client Allow List" under SNMP Access

#Remediation:
# 1-Login to Configuration utility
# 2- Go to System > SNMP > Agent > Configuration
# 3- Add trusted IP addresses in "Client Allow List"


   #
#Reference: 1. https://support.f5.com/csp/article/K13535
#CIS Controls v8 : 12.2 Establish and Maintain a Secure Network Architecture
# Establish and maintain a secure network architecture. A secure network architecture must address segmentation,
# least privilege, and availability, at a minimum. 


  end

end


control "cis-f5-#{control_id}.2-#{control_abbrev}" do

 title "[#{control_abbrev.upcase}] Ensure minimum SNMP version is set to V3 for agent access (Manual)"

  desc  "To disable the usage of weak SNMP protocols.\n\nRationale: "
  
  #Impact:
  #=========
  #Abuse of SNMP settings could allow an unauthorised third party to gain access to a network
  # device when weak SNMP protocols are used. These protocols ( prior to v3) lack the ability of authentication and encryption.
 
  #impact 0.0
  impact high

  tag cis_scored: true
  tag cis_level: 1
  tag cis_f5: "#{control_id.to_s}.2"
  tag cis_version: cis_version.to_s
  tag nist: ['AC-2']
  tag cis_version : v8
  tag cis_ig : ['IG 2','IG 3']


  describe "cis-f5-benchmark-#{control_id}.2" do
    skip 'Not implemented'

# Audit
# 1-Login to Configuration utility
# 2- Go to System > SNMP > Agent > SNMP Access (v1, v2c) : check if an entry is listed.
# 3-Go to System > SNMP > Agent > SNMP Access (v3) : Check if an entry is listed

#Remediation
# 1-Login to Configuration utility
# 2- Go to System > SNMP > Agent > SNMP Access (v1, v2c) : Select all listed entries and click “Delete”
# 3-Go to System > SNMP > Agent > SNMP Access (v3) : Make sure there is one entry at least , otherwise create one.

   #
#Reference: 1. https://support.f5.com/csp/article/K13625
#CIS Controls v8 : 12.2 Establish and Maintain a Secure Network Architecture
# Establish and maintain a secure network architecture. A secure network architecture must address segmentation,
# least privilege, and availability, at a minimum. 

  end

end

control "cis-f5-#{control_id}.3-#{control_abbrev}" do

 title "[#{control_abbrev.upcase}] Ensure to lockdown access logs to \"Administrator , Resource Administrator and Auditor \" roles only (Manual)"

  desc  "To restrict access to the system logs.\n\nRationale: "
  
 
  #impact 0.0
  impact high

  tag cis_scored: true
  tag cis_level: 1
  tag cis_f5: "#{control_id.to_s}.3"
  tag cis_version: cis_version.to_s
  tag nist: ['tbc']
  tag cis_version : v8
  tag cis_ig : ['IG 1','IG 2','IG 3']


  describe "cis-f5-benchmark-#{control_id}.3" do
    skip 'Not implemented'

# Audit
# 1-Login to Configuration utility
# 2-Go to System > Logs > Configuration > Options
# 3-Under "Log Access" , check who are allowed to access the logs.

   #Remediation
   #1-Login to Configuration utility
   # 2-Go to System > Logs > Configuration > Options
   # 3- Under Log Access : select “Allow” for: Administrator Resource Administrator Auditor Select “Deny” for other users .

   #
#Reference: 
#CIS Controls v8 : 8.1 Establish and Maintain an Audit Log Management Process
# Establish and maintain an audit log management process that defines the enterprise’s logging requirements.
# At a minimum, address the collection, review, and retention of audit logs for enterprise assets.
# Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.

  end

end


control "cis-f5-#{control_id}.4-#{control_abbrev}" do

 title "[#{control_abbrev.upcase}] Ensure that audit logging for \"MCP, tmsh and GUI\" is set to enabled (Manual)"

  desc  "To enable audit logging on configuration changes that users or services make to the BIG-IP system.\n\nRationale: "
  
  #Impact:
  #=========
  #Audit logging provides a mechanism to investigate security incidents and unauthorised activities.
  #It is also necessary for compliance auditing.
 
  #impact 0.0
  impact high

  tag cis_scored: true
  tag cis_level: 1
  tag cis_f5: "#{control_id.to_s}.4"
  tag cis_version: cis_version.to_s
  #Auditing — AU-2, CM-5
  tag nist: ['AU-2','CM-5']
  tag cis_version : v8
  tag cis_ig : ['IG 1','IG 2','IG 3']


  describe "cis-f5-benchmark-#{control_id}.4" do
    skip 'Not implemented'

# Audit
# 1-Login to Configuration utility
# 2-Go to System > Logs > Configuration > Options
# 3- Under Audit Logging : check MCP,tmsh and GUI

#Remediation
# 1-Login to Configuration utility
# 2-Go to System > Logs > Configuration > Options
# 3- Under Audit Logging : Select “Enable” for all items : “MCP” , “tmsh” and "GUI"
#
#Reference:
# 1. https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/bigip-external-monitoring-implementations-13-1-0/1.html
# 2. https://support.f5.com/csp/article/K07592334
#
#CIS Controls v8 : 8.1 Establish and Maintain an Audit Log Management Process
# Establish and maintain an audit log management process that defines the enterprise’s logging requirements.
# At a minimum, address the collection, review, and retention of audit logs for enterprise assets.
# Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.

  end

end

control "cis-f5-#{control_id}.5-#{control_abbrev}" do

 title "[#{control_abbrev.upcase}] Ensure that Remote Syslog Servers are configured (Manual)"

  desc  "To ensure that logs are sent to external servers.\n\nRationale: "
  
  #Impact:
  #=========
  #In case of hardware failure , logs stored locally can be lost. This impacts the ability of
  #investigating security incidents and be in compliance with the requirements of logs retention period .
 
  #impact 0.0
  impact high

  tag cis_scored: true
  tag cis_level: 1
  tag cis_f5: "#{control_id.to_s}.5"
  tag cis_version: cis_version.to_s
  #Syslog Configuration — AU-8, AU-9(2), AU-12(2)
  tag nist: ['AU-8','AU-9(2)','AU-12(2)']
  tag cis_version : v8
  tag cis_ig : ['IG 2','IG 3']


  describe "cis-f5-benchmark-#{control_id}.5" do
    skip 'Not implemented'

# Audit
# 1-Log in to the Configuration utility.
# 2-Go to System > Logs > Configuration > Remote Logging.
# 3-Check "Remote Syslog Server List"

#Remediation
# 1-Log in to the Configuration utility.
# 2-Go to System > Logs > Configuration > Remote Logging.
# 3-For Remote IP, enter the destination syslog server IP address, or FQDN. (DNS server configuration required)
# 4-For Remote Port, enter the remote syslog server UDP port (default is 514).
# 5-Select Add.
# 6-Select Update.


#TMSH
#=====
#Add a single remote syslog server

#Impact of procedure: Performing the following procedure should not have a negative impact on your system.

#Log in to the TMOS Shell (tmsh) by entering the following command:
#tmsh

#To add a single remote syslog server, use the following command syntax:
#modify /sys syslog remote-servers add { <name> { host <IP address or FQDN> remote-port <port> }}

#For example, to add remote syslog server 172.28.31.40 with port 514 and name mysyslog, enter the following command:

#modify /sys syslog remote-servers add { mysyslog { host 172.28.31.40 remote-port 514 }}

#Note: If you do not enter a port number, the system configures the default port number, 514.

#To save the configuration, enter the following command:
#save /sys config

#For BIG-IP systems in a high availability (HA) configuration, perform a ConfigSync to synchronize the changes to the other devices in the device group.




#
#Reference:
# https://support.f5.com/csp/article/K13080
#
#CIS Controls v8 : 8.9 Centralize Audit Logs Centralize, to the extent possible,
#audit log collection and retention across enterprise assets.

  end

end




