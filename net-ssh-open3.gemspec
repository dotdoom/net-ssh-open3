Gem::Specification.new do |s|
  s.name        = 'net-ssh-open3'
  s.version     = '0.1.4'
  s.date        = '2013-12-08'
  s.summary     = 'Thread-safe Open3 for Net::SSH'
  s.authors     = ['Artem Sheremet']
  s.email       = 'dot.doom@gmail.com'
  s.files       = ['lib/net-ssh-open3.rb', 'README.md']
  s.homepage    = 'http://github.com/dotdoom/net-ssh-open3'
  s.license     = 'MIT'
  s.add_dependency 'net-ssh', '~>2.6'
end
