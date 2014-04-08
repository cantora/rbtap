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
