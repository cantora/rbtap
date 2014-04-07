require 'hexdump'

require 'rbtap/DB'
require 'rbtap/Diff'

module RBTap

module DisplaysIntercepts

  def intercept_diff(id1, id2)
    DB::with_session_cx do |cx|
      icpt1 = DB::Intercept.find_by_id(id1)
      icpt2 = DB::Intercept.find_by_id(id2)
      if icpt1.data_equal?(icpt2)
        puts "#{id1} == #{id2}"
        show_intercept(icpt)
        return
      end

      show_intercept(icpt1)
      puts "  " + "."*(self.cols-2)
      prefix = " "*4
      dump_printer = Class.new do
        def <<(data)
          STDOUT << " "*4 << data
        end
      end

      icpt1.diff(icpt2).each_with_index do |pdiff, idx|
        s = pdiff.summary
        next if s.empty?

        puts "  packet #{idx}:"
        puts s.gsub(/^/, prefix)
        pdiff.a_value.hexdump(:output => dump_printer.new)
        pdiff.b_value.hexdump(:output => dump_printer.new)
      end
    end
  end

  def show_intercept(icpt)
    src = "#{icpt.src_endpoint.host.ip}:#{icpt.src_endpoint.port}"
    dst = "#{icpt.dst_endpoint.host.ip}:#{icpt.dst_endpoint.port}"
    puts "_"*self.cols
    puts "intercept: #{icpt.id}"
    puts "  #{src} -> #{dst}"

    to_dst_printer = Class.new do
      def initialize(width)
        @width = width
      end

      def <<(data)
        sz = data.size - 1
        w = @width - 3
        pad = (sz < w)? " "*(w - sz) : ""

        STDOUT << " "*2 << data[0..-2] << pad << " :\n"
      end
    end

    to_src_printer = Class.new do
      def initialize(width)
        @width = width
      end

      def <<(data)
        STDOUT << " "*@width << ": " << data
      end
    end

    width = 80
    icpt.packets.each do |pkt|
      pkt.value.hexdump(:output => (pkt.forward?? to_dst_printer.new(width) : to_src_printer.new(width)))
    end
  end

end #module DisplaysIntercepts

end #module RBTap