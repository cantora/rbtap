require 'singleton'
require 'active_record'
require 'digest/sha1'

require 'rbtap/Diff'

module RBTap

module DB

  class Host < ActiveRecord::Base
    has_many :endpoints, dependent: :destroy
  end

  class Endpoint < ActiveRecord::Base
    belongs_to :host

    def host
      Host.where(:id => self.host_id).first
    end
  end

  class Intercept < ActiveRecord::Base
    has_many :packets, -> { order 'seq ASC' }, :dependent => :destroy

    def data_hash
      pkt_hashes = self.packets.collect do |pkt|
        pkt.data_hash
      end.join(",")
      Digest::SHA1::hexdigest(pkt_hashes)
    end

    def data_equal?(other)
      my_pkts = self.packets
      other_pkts = other.packets
      my_pkts_size = my_pkts.size
      #puts "my_pkts_size = #{my_pkts_size}"
      #puts "other_pkts.size = #{other_pkts.size}"
      return false if my_pkts_size != other_pkts.size

      (0..my_pkts_size-1).each do |i|
        return false if !my_pkts[i].data_equal?(other_pkts[i])
      end

      return true
    end

    def diff(other)
      my_pkts = self.packets
      other_pkts = other.packets
      my_pkts_size = my_pkts.size
      other_pkts_size = other.packets.size

      diffs = []
      my_pkts.each_with_index do |pkt, i|
        if i >= other_pkts_size
          diffs << Packet::PDiff.new(pkt, nil)
        else
          diffs << my_pkts[i].diff(other_pkts[i])
        end
      end

      if my_pkts_size < other_pkts_size
        (my_pkts_size..other_pkts_size-1).each do |i|
          diffs << Packet::PDiff.new(nil, other_pkts[i])
        end
      end

      return diffs
    end

    def src_endpoint
      Endpoint.where(:id => self.endpoint_src_id).first
    end

    def dst_endpoint
      Endpoint.where(:id => self.endpoint_dst_id).first
    end

    def add_packet(value, forward, fin)
      self.transaction do
        self.packets.create(
          :value => value,
          :forward => forward,
          :fin => fin,
          :seq => self.seq
        )
        self.update(:seq => self.seq + 1)
      end
    end

    def add_packet_to_dst(value, fin=false)
      add_packet(value, true, fin)
    end

    def add_packet_to_src(value, fin=false)
      add_packet(value, false, fin)
    end
  end

  class Packet < ActiveRecord::Base
    belongs_to :intercept

    class PDiff
      attr_reader :pkt_a, :pkt_b
      def initialize(pkt_a, pkt_b)
        @pkt_a = pkt_a
        @pkt_b = pkt_b
      end

      def direction
        return "" if @pkt_a.nil? || @pkt_b.nil?

        if @pkt_a.forward == @pkt_b.forward
          return ""
        end

        return "dir: #{@pkt_a.direction} -> #{@pkt_b.direction}"
      end

      def a_value
        @pkt_a.nil?? "" : @pkt_a.value
      end

      def b_value
        @pkt_b.nil?? "" : @pkt_b.value
      end

      def value
        Diff.new(a_value(), b_value())
      end

      def value_summary
        val = self.value

        return val.to_s if !val.diffs.empty?
        return ""
      end

      def summary
        d = self.direction
        return d if !d.empty?
        return self.value_summary
      end
    end

    def data_hash
      Digest::SHA1::hexdigest(
        "#{self.forward}:#{self.fin}:#{Digest::SHA1::hexdigest(self.value)}"
      )
    end

    def data_equal?(other)
      return false if self.forward != other.forward
      return false if self.fin != other.fin
      return false if self.value != other.value

      return true
    end

    def diff(other)
      return self.class::PDiff.new(self, other)
    end

    def direction
      if self.forward
        return "to dest"
      end

      return "to source"
    end

    def to_dst?
      return self.forward == true
    end

    def to_src?
      return !self.to_dst?
    end
  end

  def self.create_intercepts_table(cx)
    name = 'intercepts'
    #puts "create table #{name}"
    cx.create_table(name) do |t|
      t.column :endpoint_src_id, :integer, {:null => false}
      t.column :endpoint_dst_id, :integer, {:null => false}
      t.column :seq, :integer, {:null => false, :default => 0}
      t.column :created_at, :datetime, {:null => false}
    end if !cx.table_exists?(name)
  end

  def self.create_endpoints_table(cx)
    name = 'endpoints'
    #puts "create table #{name}"
    cx.create_table(name) do |t|
      t.belongs_to :host
      t.column :port, :integer, {:null => false}
      t.column :created_at, :datetime, {:null => false}
    end if !cx.table_exists?(name)
  end

  def self.create_hosts_table(cx)
    name = 'hosts'
    #puts "create table #{name}"
    cx.create_table(name) do |t|
      t.column :ip, :string, {:null => false}
      t.column :created_at, :datetime, {:null => false}
    end if !cx.table_exists?(name)
  end

  def self.create_packets_table(cx)
    name = 'packets'
    #puts "create table #{name}"
    cx.create_table(name) do |t|
      t.belongs_to :intercept
      t.column :value, :binary
      t.column :forward, :boolean, {:null => false}
      t.column :fin, :boolean, {:null => false, :default => false}
      t.column :seq, :integer, {:null => false}
      t.column :created_at, :datetime, {:null => false}
    end if !cx.table_exists?(name)
  end

  class Session
    include Singleton

    def self.use(name)
      Session.instance.load(name)
    end

    def with_cx(&bloc)
      @mtx.synchronize do
        result = bloc.call(ActiveRecord::Base.connection)
        ActiveRecord::Base.clear_active_connections!
        result
      end
    end

    def load(name)
      @mtx = Mutex.new

      path = ['mitm_sessions']
      FileUtils.mkdir_p(path)
      dir = if name.nil? || name.empty?
        name = ['noname', Time.now.strftime('%Y-%m-%d,%H-%M-%S')].join('_')
      end
      path << (name + ".sqlite")

      ActiveRecord::Base.establish_connection(
        :adapter => 'sqlite3',
        :database => File.join(*path)
      )

      with_cx do |cx|
        ActiveRecord::Base.transaction do
          DB::create_hosts_table(cx)
          DB::create_endpoints_table(cx)
          DB::create_intercepts_table(cx)
          DB::create_packets_table(cx)
        end
      end
      @initialized = true
    end

    def initialized
      (@initialized == true)
    end
  end

  def self.session()
    Session.instance
  end

  def self.with_session_cx(&bloc)
    session.with_cx(&bloc)
  end

end #module DB

end #module RBTap
