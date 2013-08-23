net-ssh-open3
=============

Thread-safe Open3 for Net::SSH.

Adds some Open3-style functions to Net::SSH::Connection::Session.

See [ruby 1.9.3 doc](http://www.ruby-doc.org/stdlib-1.9.3/libdoc/open3/rdoc/Open3.html)
or [ruby 2.0 doc](http://www.ruby-doc.org/stdlib-2.0/libdoc/open3/rdoc/Open3.html)

Usage example (don't forget to `gem install net-ssh --version "~>2.6"`):

    irb(main):002:0> require './open3'
    => true
    irb(main):003:0> puts Net::SSH.start('localhost', 'root').capture2e('ls', '/boot') # also: 'ls /boot'
	grub
	initramfs-linux-fallback.img
	initramfs-linux.img
	lost+found
	memtest86+
	vmlinuz-linux
	exit 0
	=> nil

Note: a single SSH session may have several channels, i.e. you don't have to open a new connection to execute tasks in parallel.
All Open3 methods are thread-safe.

For more information please see documentation inside.
