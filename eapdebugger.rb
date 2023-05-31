#!/usr/bin/env ruby
# frozen_string_literal: true

################################################################################
#    eapdebugger.rb, an EAP packet analysis software                           #
#    Copyright (C) 2023  Jan-Frederik Rieckers <rieckers@dfn.de>               #
#                                                                              #
#    This program is free software: you can redistribute it and/or modify      #
#    it under the terms of the GNU General Public License as published by      #
#    the Free Software Foundation, either version 3 of the License, or         #
#    (at your option) any later version.                                       #
#                                                                              #
#    This program is distributed in the hope that it will be useful,           #
#    but WITHOUT ANY WARRANTY; without even the implied warranty of            #
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             #
#    GNU General Public License for more details.                              #
#                                                                              #
#    You should have received a copy of the GNU General Public License         #
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.    #
################################################################################


require 'packetfu'
require 'semantic_logger'
require_relative './localconfig'
require_relative './src/radiuspacket'

SemanticLogger.default_level = :info
SemanticLogger.add_appender(file_name: 'development.log')

logger = SemanticLogger['eapdebugger']

include PacketFu

logger.info('Start packet capture')

cap = PacketFu::Capture.new(iface: @config[:iface], start: true, filter: "port #{@config[:port] || 1812}")

cap.stream.each do |p|
  logger.trace('Packet captured.')

  pkt = PacketFu::Packet.parse p

  logger.debug 'Not an IP packet' and next unless pkt.is_ip?

  logger.debug 'Fragmented packet' and next if pkt.ip_frag & 0x2000 != 0

  logger.debug 'Not a UDP packet' and next unless pkt.is_udp?

  logger.debug 'Not the correct port' and next unless [pkt.udp_sport, pkt.udp_dport].include? (@config[:port] || 1812)

  rp = nil

  begin
    rp = RadiusPacket.new(pkt)
    next if rp.status_server?
    rp.parse_eap!
  rescue PreliminaryEAPParsingError => e
    logger.debug 'Found broken EAP packet'
    outputfile = PacketFu::PcapNG::File.new
    packets = [pkt]
    pcap_file_name = File.join('packets', "broken_#{@config[:org_name]}_#{DateTime.now.strftime('%s')}.pcap")
    outputfile.array_to_file(array: packets, file: pcap_file_name)
    logger.info "Saving RADIUS packet with broken EAP to #{pcap_file_name}"
  rescue StandardError => e
    next
  end
end
