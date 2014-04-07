#!/usr/bin/env ruby

require 'rbtap'
require 'socket'

class BasicInterceptor
  include RBTap::InterceptsTCP

  to_complete_connection do
    TCPSocket.new('localhost', 5555)
  end

end

server = TCPServer.new 5556
sess_name = ARGV[0]
if sess_name.nil? || sess_name.empty?
  puts "session name required"
  exit(1)
end

RBTap::DB::Session::use(sess_name)
RBTap::run_intercept(server) do
  BasicInterceptor.new
end
