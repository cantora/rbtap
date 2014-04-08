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
require 'rbtap/SavesIntercepts'

module RBTap

module InterceptsTCP
  include SavesIntercepts

  module ClassMethods
    def IT_complete_cx(inst, *args)
      return inst.instance_exec(*args, &@IT_complete_cx)
    end

    def to_complete_connection(&bloc)
      @IT_complete_cx = bloc
    end

  end

  def self.included(cls)
    cls.extend(ClassMethods)
  end

  def set_intercept_id(iid)
    @IT_id = iid
  end

  def IT_log_msg(name, msg)
    puts "[#{@IT_id}]#{name} #{msg.inspect}"
  end

  def sock_host_ip_port(sock)
    pn = sock.peeraddr(:numeric)
    return pn[2], pn[1]
  end

  def intercept_loop(sock_l, sock_r)
    pair = Struct.new(:name, :fd, :type)

    map = {
      sock_l => pair.new(">-->", sock_r, :dst),
      sock_r => pair.new("<--<", sock_l, :src)
    }
    saddr, sport = sock_host_ip_port(sock_l)
    daddr, dport = sock_host_ip_port(sock_r)

    read_fds, notused = IO.select(map.keys)
    read_fds.each do |fd|
      other = map[fd]

      msg = ""
      loop do
        begin
          buf = fd.recv_nonblock(4096)
        rescue IO::WaitReadable
          break
        end

        if buf.size < 1
          #TODO, we wont log any pending data from the other
          #fd. we should set a shutdown flag here and log the
          #data from the other fd (if any).
          fd.close()
          other.fd.close()
          return false
        end

        msg += buf
        sleep(0.2)
      end

      with_intercept_record(saddr, sport, daddr, dport) do |icpt|
        if other.type == :dst
          icpt.add_packet_to_dst(msg)
        else
          icpt.add_packet_to_src(msg)
        end
      end
      IT_log_msg(other.name, msg)
      other.fd.write(msg)
    end

    return true
  end

  def intercept(sock_l)
    sock_r = begin
      self.class::IT_complete_cx(self, sock_l)
    rescue Errno::ECONNREFUSED => e
      puts "error: #{e.message}"
      sock_l.close()
      return
    end

    loop do
      break if intercept_loop(sock_l, sock_r) != true
    end
  end

end #module InterceptsTCP

end #module RBTap
