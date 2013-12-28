require 'shellwords' # String#shellescape
require 'thread' # ConditionVariable
require 'net/ssh' # Monkeypatching
require 'stringio' # StringIO for capture*

class Class
  unless method_defined?(:alias_method_once)
    private
    # Create an alias +new_method+ to +old_method+ unless +new_method+ is already defined.
    def alias_method_once(new_method, old_method) #:nodoc:
      alias_method new_method, old_method unless method_defined?(new_method)
    end
  end
end

module Net::SSH
  module Process
    # Encapsulates the information on the status of remote process, similar to ::Process::Status.
    #
    # Note that it's impossible to retrieve PID (process ID) via an SSH channel (thus impossible to properly signal it).
    #
    # Although RFC4254 allows sending signals to the process (see http://tools.ietf.org/html/rfc4254#section-6.9),
    # current OpenSSH server implementation does not support this feature, though there are some patches:
    # https://bugzilla.mindrot.org/show_bug.cgi?id=1424 and http://marc.info/?l=openssh-unix-dev&m=104300802407848&w=2
    #
    # As a workaround one can request a PTY and send SIGINT or SIGQUIT via ^C, ^\ or other sequences,
    # see 'pty' option in Net::SSH::Open3 for more information.
    #
    # Open3 prepends your command with 'echo $$; ' which will echo PID of your process, then intercepts this line from STDOUT.
    class Status
      # Integer exit code in range 0..255, 0 usually meaning success.
      # Assigned only if the process has exited normally (i.e. not by a signal).
      # More information about standard exit codes: http://tldp.org/LDP/abs/html/exitcodes.html
      attr_reader :exitstatus

      # Process ID of a remote command interpreter or a remote process.
      # See note on Net::SSH::Process::Status class for more information on how this is fetched.
      # false if PID fetching was disabled.
      attr_reader :pid

      # true when process has been killed by a signal and a core dump has been generated for it.
      def coredump?
        @coredump
      end 

      # Integer representation of a signal that killed a process, if available.
      #
      # Translated to local system (so you can use Signal.list to map it to String).
      # Explanation: when local system is Linux (USR1=10) and remote is FreeBSD (USR1=30),
      # 10 will be returned in case remote process receives USR1 (30).
      #
      # Not all signal names are delivered by ssh: for example, SIGTRAP is delivered as "SIG@openssh.com"
      # and therefore may not be translated. Returns String in this case.
      def termsig
        Signal.list[@termsig] || @termsig
      end

      # true if the process has exited normally and returned an exit code.
      def exited?
        !!@exitstatus
      end

      # true if the process has been killed by a signal.
      def signaled?
        !!@termsig
      end

      # true if the process is still running (actually if we haven't received it's exit status or signal).
      def active?
        not (exited? or signaled?)
      end

      # Returns true if the process has exited with code 0, false for other codes and nil if killed by a signal.
      def success?
        exited? ? exitstatus == 0 : nil
      end

      # String representation of exit status.
      def to_s
        if @pid != nil
          "pid #@pid " <<
          if exited?
            "exit #@exitstatus"
          elsif signaled?
            "#@termsig (signal #{termsig}) core #@coredump"
          else
            'active'
          end
        else
          'uninitialized'
        end
      end

      # Inspect this instance.
      def inspect
        "#<#{self.class}: #{to_s}>"
      end
    end
  end

  # Net::SSH Open3 extensions.
  # All methods have the same argument list.
  #
  # *optional* +env+: custom environment variables +Hash+. Note that SSH server typically restricts changeable variables to a very small set,
  # e.g. for OpenSSH see +AcceptEnv+ in +/etc/ssh/sshd_config+ (+AcceptEnv+ +LANG+ +LC_*+)
  #
  # +command+: a single shell command (like in +sh+ +-c+), or an executable program.
  #
  # *optional* +arg1+, +arg2+, +...+: arguments to an executable mentioned above.
  #
  # *optional* +options+: options hash, keys:
  # * +redirects+: Hash of redirections which will be appended to a command line (you can't transfer a pipe to a remote system).
  #   Key: one of +:in+, +:out+, +:err+ or a +String+, value: +Integer+ to redirect to remote fd, +String+ to redirect to a file.
  #   If a key is a Symbol, local +IO+ may be specified as a value. In this case, block receives +nil+ for the corresponding IO.
  #   Example:
  #     { '>>' => '/tmp/log', err: 1 }
  #   translates to
  #     '>>/tmp/log 2>&1'
  #   Another example:
  #     { in: $stdin, out: $stdout, err: $stderr }
  # * +channel_retries+: +Integer+ number of retries in case of channel open failure (ssh server usually limits a session to 10 channels),
  #   or an array of [+retries+, +delay+]
  # * +stdin_data+: for +capture*+ only, specifies data to be immediately sent to +stdin+ of a remote process.
  #   stdin is immediately closed then.
  # * +logger+: an object which responds to +debug/info/warn/error+ and optionally +init/stdin/stdout/stderr+ to log debug information
  #   and data exchange stream.
  # * +fetch_pid+: prepend command with 'echo $$' and capture first line of the output as PID. Defaults to true.
  # * +pty+: true or a +Hash+ of PTY settings to request a pseudo-TTY, see Net::SSH documentation for more information.
  #   A note about sending TERM/QUIT: use modes, e.g.:
  #     Net::SSH.start('localhost', ENV['USER']).capture2e('cat', pty: {
  #         modes: {
  #           Net::SSH::Connection::Term::VINTR => 0x01020304, # INT on this 4-byte-sequence
  #           Net::SSH::Connection::Term::VQUIT => 0xdeadbeef, # QUIT on this 4-byte sequence
  #           Net::SSH::Connection::Term::VEOF => 0xfacefeed, # EOF sequence
  #           Net::SSH::Connection::Term::ECHO => 0, # disable echoing
  #           Net::SSH::Connection::Term::ISIG => 1 # enable sending signals
  #         }
  #       },
  #       stdin_data: [0xDEADBEEF].pack('L'),
  #       logger: Class.new { alias method_missing puts; def respond_to?(_); true end }.new)
  #     # log skipped ...
  #     # => ["", #<Net::SSH::Process::Status: pid 1744 QUIT (signal 3) core true>]
  #   Note that just closing stdin is not enough for PTY. You should explicitly send VEOF as a first char of a line, see termios(3).
  module Open3
    # Captures stdout only. Returns [String, Net::SSH::Process::Status]
    def capture2(*args)
      stdout = StringIO.new
      stdin_data = extract_open3_options(args)[:stdin_data]

      run_popen(*args,
                stdin: stdin_data,
                stdout: stdout) do |waiter_thread|
        [stdout.string, waiter_thread.value]
      end
    end

    # Captures stdout and stderr into one string. Returns [String, Net::SSH::Process::Status]
    def capture2e(*args)
      stdout = StringIO.new
      stdin_data = extract_open3_options(args)[:stdin_data]

      run_popen(*args,
                stdin: stdin_data,
                stdout: stdout,
                stderr: stdout) do |waiter_thread|
        [stdout.string, waiter_thread.value]
      end
    end

    # Captures stdout and stderr into separate strings. Returns [String, String, Net::SSH::Process::Status]
    def capture3(*args)
      stdout, stderr = StringIO.new, StringIO.new
      stdin_data = extract_open3_options(args)[:stdin_data]

      run_popen(*args,
                stdin: stdin_data,
                stdout: stdout,
                stderr: stderr) do |waiter_thread|
        [stdout.string, stderr.string, waiter_thread.value]
      end
    end

    # Opens pipes to a remote process.
    # Yields +stdin+, +stdout+, +stderr+, +waiter_thread+ into a block. Will wait for a process to finish.
    # Joining (or getting a value of) +waither_thread+ inside a block will wait for a process right there.
    # 'status' Thread-Attribute of +waiter_thread+ holds an instance of Net::SSH::Process::Status for a remote process.
    # Careful: don't forget to read +stderr+, otherwise if your process generates too much stderr output
    # the pipe may overload and ssh loop will get stuck writing to it.
    def popen3(*args, &block)
      redirects = extract_open3_options(args)[:redirects]
      local_pipes = []
      stdin_inner, stdin_outer = open3_ios_for(:in, redirects, local_pipes)
      stdout_outer, stdout_inner = open3_ios_for(:out, redirects, local_pipes)
      stderr_outer, stderr_inner = open3_ios_for(:err, redirects, local_pipes)

      run_popen(*args,
                stdin: stdin_inner,
                stdout: stdout_inner,
                stderr: stderr_inner,
                block_pipes: [stdin_outer, stdout_outer, stderr_outer],
                local_pipes: local_pipes,
                &block)
    end

    # Yields +stdin+, +stdout-stderr+, +waiter_thread+ into a block.
    def popen2e(*args, &block)
      redirects = extract_open3_options(args)[:redirects]
      local_pipes = []
      stdin_inner, stdin_outer = open3_ios_for(:in, redirects, local_pipes)
      stdout_outer, stdout_inner = open3_ios_for(:out, redirects, local_pipes)

      run_popen(*args,
                stdin: stdin_inner,
                stdout: stdout_inner,
                stderr: stdout_inner,
                block_pipes: [stdin_outer, stdout_outer],
                local_pipes: local_pipes,
                &block)
    end

    # Yields +stdin+, +stdout+, +waiter_thread+ into a block.
    def popen2(*args, &block)
      redirects = extract_open3_options(args)[:redirects]
      local_pipes = []
      stdin_inner, stdin_outer = open3_ios_for(:in, redirects, local_pipes)
      stdout_outer, stdout_inner = open3_ios_for(:out, redirects, local_pipes)

      run_popen(*args,
                stdin: stdin_inner,
                stdout: stdout_inner,
                block_pipes: [stdin_outer, stdout_outer],
                local_pipes: local_pipes,
                &block)
    end

    private
    def extract_open3_options(args, pop = false)
      if Hash === args.last
        pop ? args.pop : args.last
      else
        {}
      end
    end

    def open3_ios_for(name, redirects, locals)
      if redirects and user_supplied_io = redirects[name] and IO === user_supplied_io
        name == :in ? [user_supplied_io, nil] : [nil, user_supplied_io]
      else
        IO.pipe.tap { |pipes| locals.concat pipes }
      end
    end

    SSH_EXTENDED_DATA_STDERR = 1 #:nodoc:
    REMOTE_PACKET_THRESHOLD = 512 # headers etc #:nodoc:

    private_constant :SSH_EXTENDED_DATA_STDERR, :REMOTE_PACKET_THRESHOLD

    def install_channel_callbacks(channel, options)
      logger, stdin, stdout, stderr, local_pipes =
        options[:logger], options[:stdin], options[:stdout], options[:stderr], options[:local_pipes]

      if options[:fetch_pid]
        pid_initialized = false
      else
        channel.open3_waiter_thread[:status].instance_variable_set(:@pid, false)
        pid_initialized = true
      end

      channel.on_open_failed do |_channel, code, desc|
        message = "cannot open channel (error code #{code}): #{desc}"
        logger.error(message) if logger
        raise message
      end

      channel.on_data do |_channel, data|
        unless pid_initialized
          # First arrived line contains PID (see run_popen).
          pid_initialized = true
          pid, data = data.split(nil, 2)
          channel.open3_waiter_thread[:status].instance_variable_set(:@pid, pid.to_i)
          channel.open3_signal_open
          next if data.empty?
        end
        logger.stdout(data) if logger.respond_to?(:stdout)
        if stdout
          stdout.write(data)
          stdout.flush
        end
      end

      channel.on_extended_data do |_channel, type, data|
        if type == SSH_EXTENDED_DATA_STDERR
          logger.stderr(data) if logger.respond_to?(:stderr)
          if stderr
            stderr.write(data)
            stderr.flush
          end
        else
          logger.warn("unknown extended data type #{type}") if logger
        end
      end

      channel.on_request('exit-status') do |_channel, data|
        channel.open3_waiter_thread[:status].tap do |status|
          status.instance_variable_set(:@exitstatus, data.read_long)
          logger.debug("exit status arrived: #{status.exitstatus}") if logger
        end
      end

      channel.on_request('exit-signal') do |_channel, data|
        channel.open3_waiter_thread[:status].tap do |status|
          status.instance_variable_set(:@termsig, data.read_string)
          status.instance_variable_set(:@coredump, data.read_bool)
          logger.debug("exit signal arrived: #{status.termsig.inspect}, core #{status.coredump?}") if logger
        end
      end

      channel.on_eof do
        logger.debug('server reports EOF') if logger
        [stdout, stderr].each { |io| io.close if local_pipes.include?(io) && !io.closed? }
      end

      channel.on_close do
        logger.debug('channel close command received, will enforce EOF afterwards') if logger
        begin
          if stdin.is_a?(IO)
            self.stop_listening_to(stdin)
            stdin.close if !stdin.closed? && local_pipes.include?(stdin)
          end
        ensure
          channel.do_eof # Should already be done, but just in case.
        end
      end

      if stdin.is_a?(IO)
        send_packet_size = [1024, channel.remote_maximum_packet_size - REMOTE_PACKET_THRESHOLD].max
        logger.debug("will split stdin into packets with size = #{send_packet_size}") if logger
        self.listen_to(stdin) do
          begin
            data = stdin.readpartial(send_packet_size)
            logger.stdin(data) if logger.respond_to?(:stdin)
            channel.send_data(data)
          rescue EOFError
            logger.debug('sending EOF command') if logger
            self.stop_listening_to(stdin)
            channel.eof!
          end
        end
      elsif stdin.is_a?(String)
        logger.stdin(stdin) if logger.respond_to?(:stdin)
        channel.send_data(stdin)
        channel.eof!
      end
    end

    REDIRECT_MAPPING = {
      in: '<',
      out: '>',
      err: '2>'
    }
    private_constant :REDIRECT_MAPPING

    def run_popen(*args, internal_options)
      options = extract_open3_options(args, true)
      env = (args.shift if Hash === args.first) || {}
      cmdline = args.size == 1 ? args.first : Shellwords.join(args.map(&:to_s))

      redirects = options[:redirects] and redirects.each_pair do |fd_and_dir, destination|
        if destination = popen_io_name(destination)
          cmdline << " #{REDIRECT_MAPPING[fd_and_dir] || fd_and_dir}#{destination}"
        end
      end
      logger = options[:logger] || @open3_logger
      pty_options = options[:pty]
      retries, delay = options[:channel_retries]
      retries ||= 5
      delay ||= 1
      fetch_pid = options[:fetch_pid] != false
      local_pipes = Array(internal_options[:local_pipes])

      logger.init(host: self.transport.host_as_string, cmdline: cmdline,
                  env: env, pty: pty_options) if logger.respond_to?(:init)

      cmdline = "echo $$; exec #{cmdline}" if fetch_pid

      begin
        channel = open3_open_channel do |channel|
          channel.open3_signal_open unless fetch_pid
          channel.request_pty(Hash === pty_options ? pty_options : {}) if pty_options
          env.each_pair { |var_name, var_value| channel.env(var_name, var_value) }

          channel.exec(cmdline)

          install_channel_callbacks channel,
            stdin: internal_options[:stdin],
            stdout: internal_options[:stdout],
            stderr: internal_options[:stderr],
            logger: logger,
            local_pipes: local_pipes,
            fetch_pid: fetch_pid
        end.open3_wait_open
      rescue ChannelOpenFailed
        logger.warn("channel open failed: #$!, #{retries} retries left") if logger
        if (retries -= 1) >= 0
          sleep delay
          retry
        else raise
        end
      end
      logger.debug('channel is open and ready, calling user-defined block') if logger
      begin
        yield(*internal_options[:block_pipes], channel.open3_waiter_thread)
      ensure
        channel.wait
      end
    ensure
      local_pipes.each { |io| io.close unless io.closed? }
    end

    def popen_io_name(name)
      case name
      when Fixnum then "&#{name}"
      when String then Shellwords.shellescape(name)
      end
    end
  end

  module Connection
  class Session
    include Open3

    attr_accessor :open3_logger

    alias_method_once :initialize_without_open3, :initialize
    # Overridden version of +initialize+ which starts an Open3 SSH loop.
    # @private
    def initialize(*args, &block)
      initialize_without_open3(*args, &block)

      @open3_channels_mutex = Mutex.new

      # open3_ping method will pull waiter thread out of select(2) call
      # to update watched Channels and IOs and process incomes.
      @open3_pinger_reader, @open3_pinger_writer = IO.pipe
      listen_to(@open3_pinger_reader) { @open3_pinger_reader.readpartial(1) }

      @session_loop = Thread.new { open3_loop }
    end

    alias_method_once :close_without_open3, :close
    def close(*args, &block)
      @open3_closing = true
      close_without_open3(*args, &block).tap { open3_ping rescue nil }
    end

    private
    def open3_open_channel(type = 'session', *extra, &on_confirm)
      @open3_channels_mutex.synchronize do
        local_id = get_next_channel_id
        channel = Connection::Channel.new(self, type, local_id, @max_pkt_size, @max_win_size, &on_confirm)
        channel.open3_waiter_thread = Thread.new do
          status = Thread.current[:status] = Process::Status.new
          @open3_channels_mutex.synchronize do
            msg = Buffer.from(:byte, CHANNEL_OPEN, :string, type, :long, local_id,
                              :long, channel.local_maximum_window_size,
                              :long, channel.local_maximum_packet_size, *extra)
            send_message(msg)
            channels[local_id] = channel
            open3_ping

            channel.open3_close_semaphore.wait(@open3_channels_mutex) if channels.key?(channel.local_id)
          end
          raise *channel.open3_exception if channel.open3_exception
          status
        end

        channel
      end
    end

    def open3_ping
      @open3_pinger_writer.write(?P)
    end

    def open3_loop
      r, w = nil
      while not closed?
        @open3_channels_mutex.synchronize do
          break unless preprocess { not closed? } # This may remove some channels.
          r = listeners.keys
          w = r.select { |w2| w2.respond_to?(:pending_write?) && w2.pending_write? }
        end

        break if @open3_closing
        readers, writers, = Compat.io_select(r, w, nil, nil)
        postprocess(readers, writers)
      end

      channels.each do |_id, channel|
        @open3_channels_mutex.synchronize do
          channel.open3_signal_open
          channel.open3_signal_close
          channel.do_close
        end
      end
    rescue
      warn "Caught exception in an Open3 loop: #$!; thread terminating, connections will hang."
    ensure
      [@open3_pinger_reader, @open3_pinger_writer].each(&:close)
    end
  end

  # All methods in this class were created for private use of Net::SSH::Open3.
  # You probably won't need to call them directly.
  # @private
  class Channel
    # A semaphore to flag this channel as closed.
    attr_reader :open3_close_semaphore

    # An exception tracked during channel opening, if any.
    attr_reader :open3_exception

    # Waiter thread that watches this channel.
    attr_reader :open3_waiter_thread

    alias_method_once :initialize_without_open3, :initialize
    # Overridden version of +initialize+ which creates synchronization objects.
    def initialize(*args, &block)
      initialize_without_open3(*args, &block)
      @open3_close_semaphore = ConditionVariable.new

      @open3_open_mutex = Mutex.new
      @open3_open_semaphore = ConditionVariable.new
    end

    alias_method_once :do_close_without_open3, :do_close
    # Overridden version of +do_close+ which tracks exceptions and sync.
    def do_close(*args)
      do_close_without_open3(*args)
    rescue
      @open3_exception = $!
    ensure
      open3_signal_close
    end

    alias_method_once :do_open_confirmation_without_open3, :do_open_confirmation
    # Overridden version of +do_open_confirmation+ which tracks exceptions.
    def do_open_confirmation(*args)
      do_open_confirmation_without_open3(*args)
      # Do not signal right now: we will signal as soon as PID arrives.
    rescue
      @open3_exception = $!
    end

    alias_method_once :do_open_failed_without_open3, :do_open_failed
    # Overridden version of +do_open_failed+ which tracks exceptions and sync.
    def do_open_failed(*args)
      do_open_failed_without_open3(*args)
    rescue
      @open3_exception = $!
    ensure
      open3_signal_open
      open3_signal_close
    end

    # +waiter_thread+ setter which may only be called once with non-false argument.
    def open3_waiter_thread=(value)
      @open3_waiter_thread = value unless @open3_waiter_thread
    end

    # Suspend current thread execution until this channel is opened.
    # Raises an exception if tracked during opening.
    def open3_wait_open
      @open3_open_mutex.synchronize { @open3_open_semaphore.wait(@open3_open_mutex) }
      raise *open3_exception if open3_exception
      self
    end

    # Wait for this channel to be closed.
    def wait
      @open3_waiter_thread.join
      self
    end

    # Flag this channel as opened and deliver signals.
    def open3_signal_open
      @open3_open_mutex.synchronize { @open3_open_semaphore.signal }
    end

    # Flag this channel as closed and deliver signals.
    # Should be called from within session's mutex.
    def open3_signal_close
      @open3_close_semaphore.signal
    end
  end
  end
end
