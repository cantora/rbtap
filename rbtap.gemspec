
Gem::Specification.new do |s|
  s.name        = 'rbtap'
  s.version     = '0.0.1'
  s.date        = '2014-04-07'
  s.summary     = 'intercept socket connections for analysis'
  s.description = 'intercept socket connections for analysis'
  s.authors     = ['anthony cantor']
  s.add_runtime_dependency 'hexdump', ' >= 0.2.3', ' < 1.0'
  s.add_runtime_dependency 'activerecord', ' >= 4.0.4', ' < 5.0'
  s.files       = [File.join('lib', 'rbtap.rb')] + [
    'Diff.rb',
    'InterceptViewer.rb',
    'DisplaysIntercepts.rb',
    'SavesIntercepts.rb',
    'DB.rb',
    'InterceptsTCP.rb'
  ].map {|x| File.join('lib', 'rbtap', x) }
  s.license       = 'GPLv2'
  s.executables   = ['rbtap-analyze']
end
