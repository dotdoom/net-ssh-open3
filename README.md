net-ssh-open3
=============

[![Gem Version](https://badge.fury.io/rb/net-ssh-open3.png)](http://badge.fury.io/rb/net-ssh-open3)

Thread-safe Open3 for Net::SSH.

Adds some Open3-style functions to Net::SSH::Connection::Session.

See [ruby 1.9.3 doc](http://www.ruby-doc.org/stdlib-1.9.3/libdoc/open3/rdoc/Open3.html)
or [ruby 2.0 doc](http://www.ruby-doc.org/stdlib-2.0/libdoc/open3/rdoc/Open3.html).

Usage example:

    irb(main):001:0> require 'net-ssh-open3'
    => true
    irb(main):002:0> session = Net::SSH.start('localhost', 'root'); nil
    => nil
    irb(main):003:0> puts session.capture2e('ls', '/boot') # also: 'ls /boot'
    grub
    initramfs-linux-fallback.img
    initramfs-linux.img
    lost+found
    memtest86+
    vmlinuz-linux
    pid 1594 exit 0
    => nil
    irb(main):004:0> session.popen2e('sh') { |i, oe, w| i.puts('kill $$'); w[:status] }
    => #<Net::SSH::Process::Status: pid 16864 TERM (signal 15) core false>

Note: a single SSH session may have several channels, i.e. you may run several Open3 methods on the same session in parallel (in different threads).

For more information please see documentation inside.
