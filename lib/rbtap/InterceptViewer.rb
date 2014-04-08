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
require 'optparse'
require 'logger'

require 'rbtap/DisplaysIntercepts'
require 'rbtap/DB'

module RBTap

class InterceptViewer
  include DisplaysIntercepts
  CMDS = ["show", "diff"]

  def self.parse(argv)
    options = {
      :verbose       => 0,
      :ids           => []
    }

    optparse = OptionParser.new do |opts|
      opts.banner = "usage: #{File.basename(__FILE__)} [options] CMD"
      opts.separator ""

      opts.separator "commands: #{CMDS.join(", ")}"
      opts.separator ""

      opts.separator "common options:"

      opts.on('--id ID', 'id of an intercept to work with') do |i|
        options[:ids] << i
      end

      opts.on('-q', '--query QUERY', 'query which select ids of intercepts to work with') do |q|
        options[:query] = q
      end

      opts.on('-d', '--dbname DBNAME', 'database name' ) do |dbname|
        options[:dbname] = dbname
      end

      opts.on('-v', '--verbose', 'verbose output') do
        options[:verbose] += 1
      end

      h_help = 'display this message.'
      opts.on('-h', '--help', h_help) do
        raise ArgumentError.new,  ""
      end
    end

    begin
      optparse.parse!(argv)

      options[:cmd] = argv.shift
      raise ArgumentError, "must specify a command" if !options[:cmd]
      raise ArgumentError, "must specify --dbname" if !options[:dbname]
      raise ArgumentError, "must specify --query or --id" if !options[:query] && options[:ids].empty?

    rescue ArgumentError => e
      puts e.message if !e.message.empty?
      puts optparse

      exit
    end

    return options
  end #self.parse

  def initialize(options)
    @options = options
    @log = Logger.new($stderr)
    @log.formatter = proc do |sev, t, pname, msg|
      Thread.current.object_id.to_s(16) + ":" + msg + "\n"
    end

    @log.level = case @options[:verbose]
    when 0
      Logger::WARN
    when 1
      Logger::INFO
    else
      Logger::DEBUG
    end

  end

  def run
    @log.debug("options: #{@options.inspect}")
    DB::Session.use(@options[:dbname])

    case @options[:cmd]
    when "diff"
      cmd_diff
    when "show"
      cmd_show
    end
  end

  def cols
    cols = `tput cols`.strip.to_i
    cols = 80 if cols < 1
    return cols
  end

  def get_ids_from_args(cx)
    if @options[:ids].empty?
      cx.select_values(@options[:query])
    else
      @options[:ids]
    end
  end

  def cmd_diff
    ids = DB::with_session_cx do |cx|
      get_ids_from_args(cx)
    end

    if ids.size < 2
      raise ArgumentError, "diff: not enough ids"
    end

    (1..ids.size-1).each do |idx|
      id1 = ids[idx-1].to_i
      id2 = ids[idx].to_i
      intercept_diff(id1, id2)
    end
  end

  def cmd_show
    history = {}
    DB::with_session_cx do |cx|
      ids = get_ids_from_args(cx)
      ids.each do |id|
        icpt = DB::Intercept.find_by_id(id)
        digest = icpt.data_hash
        prev = history[digest]
        if !prev.nil?
          puts "intercept #{id} is identical to intercept #{prev.id}"
          next
        end
        history[digest] = icpt

        show_intercept(icpt)
      end
    end
  end


end #class InterceptViewer

end #module RBTap
