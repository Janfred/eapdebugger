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

@deduplication = []

cap = PacketFu::Capture.new(iface: @config[:iface], start: true, filter: "port #{@config[:port] || 1812}")

def deduplicate(radius_packet)

  to_delete = []
  @deduplication.each do |dedup|
    if dedup[:last_seen] + 30 < Time.now
      to_delete << dedup
      next
    end
    next if dedup[:id] != radius_packet.identifier
    next if dedup[:auth] != radius_packet.authenticator
    next if dedup[:udp] != radius_packet.udp

    dedup[:last_seen] = Time.now
    return true
  end

  to_delete.each do |t|
    @deduplication.delete t
  end

  @deduplication << {
    id: radius_packet.identifier,
    auth: radius_packet.authenticator,
    udp: radius_packet.udp,
    last_seen: Time.now
  }
  return false
end

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
    if deduplicate(rp)
      logger.info "Found duplicate packet with ID #{rp.identifier}. Not saving."
      next
    end
    outputfile = PacketFu::PcapNG::File.new
    packets = [pkt]
    pcap_file_name = File.join('packets', "broken_#{@config[:org_name]}_#{DateTime.now.strftime('%s')}.pcap")
    outputfile.array_to_file(array: packets, file: pcap_file_name)
    logger.info "Saving RADIUS packet with broken EAP (ID #{rp.identifier}) to #{pcap_file_name}"
  rescue StandardError => e
    next
  end
end
