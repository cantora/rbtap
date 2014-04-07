
module RBTap

  def self.run_intercept(server, &bloc)
    i = 0
    loop do
      Thread.start(server.accept) do |sock|
        Thread.current.abort_on_exception = true
        id = sprintf("%04x", i)
        icptr = bloc.call()
        icptr.set_intercept_id(id)
        puts "started intercept #{id}"
        icptr.intercept(sock)
        i += 1
      end
    end
  end

end

[
  'InterceptsTCP',
  'DisplaysIntercepts',
  'DB',
  'InterceptViewer'
].each {|x| require File.join('rbtap', x)}
