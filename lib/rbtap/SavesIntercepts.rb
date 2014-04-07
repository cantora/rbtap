require 'rbtap/DB'

module RBTap

module SavesIntercepts

  def with_intercept_record(src, src_port, dst, dst_port, &bloc)
    icpt = DB::with_session_cx do
      ActiveRecord::Base.transaction do
        src_host = DB::Host.where(:ip => src).first_or_create
        dst_host = DB::Host.where(:ip => src).first_or_create
        endpoints = {}
        endpoints[:endpoint_src_id] = DB::Endpoint.where(
          :host_id => src_host.id,
          :port => src_port
        ).first_or_create.id
        endpoints[:endpoint_dst_id] = DB::Endpoint.where(
          :host_id => dst_host.id,
          :port => dst_port
        ).first_or_create.id
        DB::Intercept.where(endpoints).first_or_create
      end
    end

    return bloc.nil?? icpt : bloc.call(icpt)
  end

end

end
