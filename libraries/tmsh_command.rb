class TMSHCommand < Inspec.resource(1)
    name 'tmsh_command'
    # supports platform: 'BIG-IP'
    desc 'Run TMSH commands via InSpec'
    example <<~EOX
      # Any output indicates
      cmd = 'tmsh list auth password-policy'
  
      describe tmsh_command(cmd) do
        its('exit_status') { should cmp 0 }
        its('stdout') { should_not cmp '' }
      end
    EOX
  
    attr_reader :command
  
    def initialize(command = nil)
      if command.nil?
        raise Inspec::Exceptions::ResourceFailed,
              'This resource requires a command as an argument'
      end
  
      @command = command
    end
  
    def result
      @result ||= inspec.backend.run_command(command)
    end
  
    def stdout
      result.stdout
    end
  
    def stderr
      result.stderr
    end
  
    def exit_status
      result.exit_status.to_i
    end
  
    def to_s
      "TMSH #{@command}"
    end
  end