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

title '3 GUI Interface Management'

control 'cis-f5-benchmark-3.1' do
  title 'Ensure \'Idle timeout\' is less than or equal to 10 minutes for Configuration utility sessions (Automated)'
  desc  "To set an idle timeout for GUI sessions.\n\nRationale: Unattended administrative sessions may provide illegal access to the device."
  impact 0.0

  tag cis: 'f5:3.1'
  tag level: 1

  describe 'cis-f5-benchmark-3.1' do
    skip 'Not implemented'
  end
end

control 'cis-f5-benchmark-3.2' do
  title 'Ensure access to Configuration utility by clients using TLS version 1.2 or later (Automated)'
  desc  "TLSv1.2 should be used for GUI connections.\n\nRationale: Restricting the configuration utility to use TLS version 1.2 is recommended."
  impact 0.0

  tag cis: 'f5:3.2'
  tag level: 1

  describe 'cis-f5-benchmark-3.2' do
    skip 'Not implemented'

#tmsh modify /sys httpd ssl-protocol "TLSv1.2"

#Reference: https://support.f5.com/csp/article/K02321234
#CIS Controls v8 : 4.2 Establish and Maintain a Secure Configuration Process for Network Infrastructure
# Establish and maintain a secure configuration process for network devices.
# Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.

  end
end

control 'cis-f5-benchmark-3.3' do
    title 'Ensure access to Configuration utility is restricted to needed IP addresses only (Automated)'
    desc  "It is recommended to maintain secure access to the GUI by allowing only trusted IP addresses or range of IP addresses.\n\nRationale: Any compromised network device within enterprise network would gain illegal access to F5 configuration utility abusing existing unresolved vulnerabilities"
    impact 0.0
  
    tag cis: 'f5:3.3'
    tag level: 1
  
    describe 'cis-f5-benchmark-3.3' do
      skip 'Not implemented'

#tmsh modify /sys httpd allow replace-all-with { <IP address or IP address range> }      
#
# References:
# 1. https://support.f5.com/csp/article/K13309
# CIS Controls v8 : 4.2 Establish and Maintain a Secure Configuration Process for Network Infrastructure
# Establish and maintain a secure configuration process for network devices.
# Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.

end
  end
  