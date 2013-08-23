net-ssh-open3
=============

Thread-safe Open3 for Net::SSH.

Adds some Open3-style functions to Net::SSH::Connection::Session.

Quote from [ruby 1.9.3 doc](http://www.ruby-doc.org/stdlib-1.9.3/libdoc/open3/rdoc/Open3.html)
> ::popen3 : pipes for stdin, stdout, stderr
> ::popen2 : pipes for stdin, stdout
> ::popen2e : pipes for stdin, merged stdout and stderr
> ::capture3 : give a string for stdin. get strings for stdout, stderr
> ::capture2 : give a string for stdin. get a string for stdout
> ::capture2e : give a string for stdin. get a string for merged stdout and stderr

Argument list is similar to Ruby:

[optional env hash], <command> [, arg1 [, arg2 ... ] ] [, options]

Known options:
* pty: PTY options
* redirects: redirect hash with filenames or fd: { out: '/tmp/output', 2: 1 }
* channel_retries: a number of retries or Array [number, delay] to open channel (in case session is busy, typically a limit is 10 channels)
* logger: logger capable of debug/info/warn/error and optinally stdin/stdout/stderr/init methods

Usage example (`gem install net-ssh --version "~>2.6"`):

    irb(main):001:0> require 'net/ssh'
    => true
    irb(main):002:0> require './open3'
    => true
    irb(main):003:0> Net::SSH.start('localhost', 'root').capture2e('ls', '/boot') # also: 'ls /boot'
    => ["grub\ninitramfs-linux-fallback.img\ninitramfs-linux.img\nlost+found\nmemtest86+\nvmlinuz-linux\n", #<Net::SSH::Process::Status: exit 0>]

Note: a single SSH session may have several channels, i.e. you don't have to open a new connection to execute tasks in parallel.
All Open3 methods alone are thread-safe.
