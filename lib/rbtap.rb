#Copyright 2014 anthony cantor
#This file is part of rbtap.
#
#rbtap is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#rbtap is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with rbtap.  If not, see <http://www.gnu.org/licenses/>.

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
