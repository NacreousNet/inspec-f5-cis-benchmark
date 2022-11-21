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

title '2 AAA'

control 'cis-f5-benchmark-2.1' do
  title 'Ensure that Remote Radius is used for Authentication Only (Automated)'
  desc  "To specify the authentication mechanism that F5 systems use for external (remote) users.\n\nRationale: Uncontrolled and illegitimate authentication could provide access to unauthorized users."
  impact 0.0

  tag cis: 'f5:2.1'
  tag level: 2

  tag nist: ['AC-6','IA-2']

  describe 'cis-f5-benchmark-2.1' do
    skip 'Not implemented'
  end
end

control 'cis-f5-benchmark-2.2' do
  title 'Ensure redundant remote authentication servers are configured (Manual)'
  desc  "Having multiple points of authentication is important in the event that the primary remote authentication source goes down.\n\nRationale: To make sure the redundant Radius servers are configured."
  impact 0.0

  tag cis: 'f5:2.2'
  tag level: 2

  tag nist: ['IA-2','IA-3']

  describe 'cis-f5-benchmark-2.2' do
    skip 'Not implemented'
  end
end

control 'cis-f5-benchmark-2.3' do
    title 'Ensure that "Fallback to local" option is disabled for Remote Authentication Settings (Manual)'
    desc  "To prevent the system from checking local DB for remote users authentication.\n\nRationale: "
    impact 0.0
  
    tag cis: 'f5:2.3'
    tag level: 2

    #User Authentication/Directory Service — AC-6, IA-2
    tag nist: ['AC-6','IA2']
  
    describe 'cis-f5-benchmark-2.3' do
      skip 'Not implemented'

    end
  end
 
  control 'cis-f5-benchmark-2.4' do
    title 'Ensure External Users\' role is set to "No Access" (Automated)'
    desc  "To set a default role for remote users Authentication and authorization for remote users are handled by third party system.\n\nRationale: "
    impact 0.0
  
    tag cis: 'f5:2.4'
    tag level: 2

    #User Authentication/Directory Service — AC-6, IA-2
    tag nist: ['AC-6','IA-2']
  
    describe 'cis-f5-benchmark-2.4' do
      skip 'Not implemented'

    end
  end
  
  control 'cis-f5-benchmark-2.5' do
    title 'Ensure External Users\' has access to needed Partitions only (Automated)'
    desc  "To limit access for remote users to needed partitions only granting a user access to \"All Partitions\" might provide the users unauthorized access.\n\nRationale: "
    impact 0.0
  
    tag cis: 'f5:2.5'
    tag level: 2
  
    describe 'cis-f5-benchmark-2.5' do
      skip 'Not implemented'

    end
  end

  control 'cis-f5-benchmark-2.6' do
    title 'Ensure External Users\' Terminal Access is Disabled (Automated)'
    desc  "To prevent remote users from gaining terminal access.\n\nRationale: "
    impact 0.0
  
    tag cis: 'f5:2.6'
    tag level: 2

        #User Authentication/Directory Service — AC-6, IA-2
        tag nist: ['AC-6','IA-2']
  
    describe 'cis-f5-benchmark-2.6' do
      skip 'Not implemented'

    end
  end

 