#rbtap

rbtap is a socket proxy library which will store packets into
a local database for later analysis. it also has a
command line utility called rbtap-analysis that displays
socket conversations and diffs packets against each other.

##example

```
$> cat rbtap_example.rb
#!/usr/bin/env ruby

require 'rbtap'
require 'socket'

class BasicInterceptor
  include RBTap::InterceptsTCP

  to_complete_connection do
    TCPSocket.new('8.8.8.8', 53)
  end

end

server = TCPServer.new 5553
sess_name = ARGV[0]
if sess_name.nil? || sess_name.empty?
  puts "session name required"
  exit(1)
end

RBTap::DB::Session::use(sess_name)
RBTap::run_intercept(server) do
  BasicInterceptor.new
end
$> ruby rbtap_example.rb dns_example #at this point make some DNS queries to 127.0.0.1:5553
started intercept 0000
[0000]>--> "\x00\x1D\xF5\xFA\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\aexample\x03com\x00\x00\x01\x00\x01"
[0000]<--< "\x00-\xF5\xFA\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\aexample\x03com\x00\x00\x01\x00\x01\xC0\f\x00\x01\x00\x01\x00\x00\x0EK\x00\x04]\xB8\xD8w"
started intercept 0001
[0001]>--> "\x00\x1D\x06^\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\aexample\x03com\x00\x00\x0F\x00\x01"
[0001]<--< "\x00V\x06^\x81\x80\x00\x01\x00\x00\x00\x01\x00\x00\aexample\x03com\x00\x00\x0F\x00\x01\xC0\f\x00\x06\x00\x01\x00\x00\x02\xED\x00-\x03sns\x03dns\x05icann\x03org\x00\x03noc\xC0-w\xFD\x85^\x00\x00\x1C \x00\x00\x0E\x10\x00\x12u\x00\x00\x00\x0E\x10"
^C
$> rbtap-analyze -d dns_example -q 'select * from intercepts' show
____________________________________________________________________________________________________________________________________________________________________________________
intercept: 1
  127.0.0.1:51639 -> 127.0.0.1:53
  00000000  00 1d f5 fa 01 00 00 01 00 00 00 00 00 00 07 65  |...............e| :
  00000010  78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01     |xample.com.....|  :
                                                                                : 00000000  00 2d f5 fa 81 80 00 01 00 01 00 00 00 00 07 65  |.-.............e|
                                                                                : 00000010  78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01 c0  |xample.com......|
                                                                                : 00000020  0c 00 01 00 01 00 00 0e 4b 00 04 5d b8 d8 77     |........K..]..w|
____________________________________________________________________________________________________________________________________________________________________________________
intercept: 2
  127.0.0.1:51644 -> 127.0.0.1:53
  00000000  00 1d 06 5e 01 00 00 01 00 00 00 00 00 00 07 65  |...^...........e| :
  00000010  78 61 6d 70 6c 65 03 63 6f 6d 00 00 0f 00 01     |xample.com.....|  :
                                                                                : 00000000  00 56 06 5e 81 80 00 01 00 00 00 01 00 00 07 65  |.V.^...........e|
                                                                                : 00000010  78 61 6d 70 6c 65 03 63 6f 6d 00 00 0f 00 01 c0  |xample.com......|
                                                                                : 00000020  0c 00 06 00 01 00 00 02 ed 00 2d 03 73 6e 73 03  |..........-.sns.|
                                                                                : 00000030  64 6e 73 05 69 63 61 6e 6e 03 6f 72 67 00 03 6e  |dns.icann.org..n|
                                                                                : 00000040  6f 63 c0 2d 77 fd 85 5e 00 00 1c 20 00 00 0e 10  |oc.-w..^... ....|
                                                                                : 00000050  00 12 75 00 00 00 0e 10                          |..u.....|
$> rbtap-analyze -d dns_example -q 'select * from intercepts' diff #packet-wise diff intercept 1 against intercept 2
____________________________________________________________________________________________________________________________________________________________________________________
intercept: 1
  127.0.0.1:51639 -> 127.0.0.1:53
  00000000  00 1d f5 fa 01 00 00 01 00 00 00 00 00 00 07 65  |...............e| :
  00000010  78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01     |xample.com.....|  :
                                                                                : 00000000  00 2d f5 fa 81 80 00 01 00 01 00 00 00 00 07 65  |.-.............e|
                                                                                : 00000010  78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01 c0  |xample.com......|
                                                                                : 00000020  0c 00 01 00 01 00 00 0e 4b 00 04 5d b8 d8 77     |........K..]..w|
  ..................................................................................................................................................................................
  packet 0:
    3,4c3,4
    < "\xF5"
    < "\xFA"
    ---
    > "\x06"
    > "^"
    29c29
    < "\x01"
    ---
    > "\x0F"
    00000000  00 1d f5 fa 01 00 00 01 00 00 00 00 00 00 07 65  |...............e|
    00000010  78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01     |xample.com.....|
    00000000  00 1d 06 5e 01 00 00 01 00 00 00 00 00 00 07 65  |...^...........e|
    00000010  78 61 6d 70 6c 65 03 63 6f 6d 00 00 0f 00 01     |xample.com.....|
  packet 1:
    2,4c2,4
    < "-"
    < "\xF5"
    < "\xFA"
    ---
    > "V"
    > "\x06"
    > "^"
    10d9
    < "\x01"
    12a12
    > "\x01"
    29c29
    < "\x01"
    ---
    > "\x0F"
    35c35
    < "\x01"
    ---
    > "\x06"
    40,41c40,41
    < "\x0E"
    < "K"
    ---
    > "\x02"
    > "\xED"
    43,46c43,68
    < "\x04"
    < "]"
    < "\xB8"
    < "\xD8"
    ---
    > "-"
    > "\x03"
    > "s"
    > "n"
    > "s"
    > "\x03"
    > "d"
    > "n"
    > "s"
    > "\x05"
    > "i"
    > "c"
    > "a"
    > "n"
    > "n"
    > "\x03"
    > "o"
    > "r"
    > "g"
    > "\x00"
    > "\x03"
    > "n"
    > "o"
    > "c"
    > "\xC0"
    > "-"
    47a70,88
    > "\xFD"
    > "\x85"
    > "^"
    > "\x00"
    > "\x00"
    > "\x1C"
    > " "
    > "\x00"
    > "\x00"
    > "\x0E"
    > "\x10"
    > "\x00"
    > "\x12"
    > "u"
    > "\x00"
    > "\x00"
    > "\x00"
    > "\x0E"
    > "\x10"
    00000000  00 2d f5 fa 81 80 00 01 00 01 00 00 00 00 07 65  |.-.............e|
    00000010  78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01 c0  |xample.com......|
    00000020  0c 00 01 00 01 00 00 0e 4b 00 04 5d b8 d8 77     |........K..]..w|
    00000000  00 56 06 5e 81 80 00 01 00 00 00 01 00 00 07 65  |.V.^...........e|
    00000010  78 61 6d 70 6c 65 03 63 6f 6d 00 00 0f 00 01 c0  |xample.com......|
    00000020  0c 00 06 00 01 00 00 02 ed 00 2d 03 73 6e 73 03  |..........-.sns.|
    00000030  64 6e 73 05 69 63 61 6e 6e 03 6f 72 67 00 03 6e  |dns.icann.org..n|
    00000040  6f 63 c0 2d 77 fd 85 5e 00 00 1c 20 00 00 0e 10  |oc.-w..^... ....|
    00000050  00 12 75 00 00 00 0e 10                          |..u.....|

```

##status
currently rbtap has a nasty bug having to do with activerecord: after 5
interceptions are captured activerecord seems to run out of database
connections from the connection pool. i think this has something to do
with different threads "checking out" the connections without
returning them...

