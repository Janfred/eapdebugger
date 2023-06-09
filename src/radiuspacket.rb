# frozen_string_literal: true

# Preliminary error, raised if the EAP message contained in the RADIUS message is malformed
class PreliminaryEAPParsingError < StandardError; end

# Error to be raised if the actual length of the packet does not match the specified length.
# This could happen if the IP packet was fragmented or the RADIUS Packet is faulty.
class PacketLengthNotValidError < StandardError; end

# A Radius Packet with all attributes and a reassembled EAP Message
class RadiusPacket
  include SemanticLogger::Loggable

  # All supported RADIUS Types
  module Type
    # Access-Request (Sent by client)
    REQUEST   =  1
    # Access-Accept (Sent by server, final answer)
    ACCEPT    =  2
    # Access-Reject (Sent by server, final answer)
    REJECT    =  3
    # Access-Challenge (Sent by server if not final answer)
    CHALLENGE = 11
    # Status Server (Sent by client to check if server is alive)
    STATUS_SERVER = 12

    # Get Attribute name by the given code
    # @param code [Byte] Code of the Attribute
    # @return [String] Name of the Attribute, or "UNKNOWN_ATTRIBUTE_<num>" if Attribute is unknown.
    def self.get_type_name_by_code(code)
      return nil if code.nil?

      Type.constants.each do |const|
        next if Type.const_get(const) != code

        return const.to_s
      end
      "UNKNOWN_TYPE_#{code}"
    end
  end

  # All supported RADIUS attributes
  module Attribute
    # RADIUS Attribute Username
    USERNAME             =   1
    # RADIUS Attribute User Password
    USERPASSWORD         =   2
    # RADIUS Attribute NAS IP-Address
    NASIPADDRESS         =   4
    # RADIUS Attribute NAS Port
    NASPORT              =   5
    # RADIUS Attribute Service type
    SERVICETYPE          =   6
    # RADIUS Attribute Framed Protocol
    FRAMEDPROTOCOL       =   7
    # RADIUS Attribute Framed IP-Address
    FRAMEDIPADDRESS      =   8
    # RADIUS Attribute Framed IP Netmask
    FRAMEDIPNETMASK      =   9
    # RADIUS Attribute Framed Routing
    FRAMEDROUTING        =  10
    # RADIUS Attribute Framed MTU
    FRAMEDMTU            =  12
    # RADIUS Attribute Framed Compression
    FRAMEDCOMPRESSION    =  13
    # RADIUS Attribute Login IP Host
    LOGINIPHOST          =  14
    # RADIUS Attribute Replymessage
    REPLYMESSAGE         =  18
    # RADIUS Attribute Remote access service
    REMOTEACCESSSERVICE  =  22
    # RADIUS Attribute State
    # Used for Mapping Requests to previous Challenges
    STATE                =  24
    # RADIUS Attribute Vendor specific
    # Used for sending Cryptographic information for WPA2-Enterprise
    VENDORSPECIFIC       =  26
    # RADIUS Attribute Session Timeout
    SESSIONTIMEOUT       =  27
    # RADIUS Attribute Called Station ID
    # Used to send the MAC Address of the Access Point the client connects to
    CALLEDSTATIONID      =  30
    # RADIUS Attribute Calling Station ID
    # Used to send the MAC Address of the Client. Mandatory for Eduroam
    CALLINGSTATIONID     =  31
    # RADIUS Attribute NAS Identifier
    NASIDENTIFIER        =  32
    # RADIUS Attribute ProxyState
    # Used by software like RADSECPROXY to save relaying state
    PROXYSTATE           =  33
    # RADIUS Attribute Acct Session ID
    # Used for Accounting
    ACCTSESSIONID        =  44
    # RADIUS Attribute Acct MultiSession ID
    # Used for Accounting
    ACCTMULTISESSIONID   =  50
    # RADIUS Attribute Event Timestamp
    EVENTTIMESTAMP       =  55
    # RADIUS Attribute NAS Port-Type
    NASPORTTYPE          =  61
    # RADIUS Attribute Tunnel Type
    # Used for Dynamic VLAN Assignment
    TUNNELTYPE           =  64
    # RADIUS Attribute Tunnel Medium Type
    # Used for Dynamic VLAN Assignment
    TUNNELMEDIUMTYPE     =  65
    # RADIUS Attribute Tunnel client endpoint
    TUNNELCLIENTENDPOINT =  66
    # RADIUS Attribute Connect Info
    # Used to encode WLAN Information (e.g. Bitrate, Band)
    CONNECTINFO          =  77
    # RADIUS Attribute Configuration Token
    CONFIGURATIONTOKEN   =  78
    # RADIUS Attribute EAP Message
    # Used to send EAP-Messages
    EAPMESSAGE           =  79
    # RADIUS Attribute Message Authenticator
    # Used to check integrity of the RADIUS packet
    MESSAGEAUTHENTICATOR =  80
    # RADIUS Attribute Tunnel Private Group ID
    # Used for Dynamic VLAN Assignment
    TUNNELPRIVATEGROUPID =  81
    # RADIUS Attribute NAS Port ID
    NASPORTID            =  87
    # RADIUS Attribute Chargeable User Identity (CUI)
    CUI                  =  89
    # RADIUS Attribute NAS IPv6-Address
    NASIPV6ADDRESS       =  95
    # RADIUS Attribute Framed Interface ID
    FRAMEDINTERFACEID    =  96
    # RADIUS Attribute Framed IPv6 Prefix
    FRAMEDIPV6PREFIX     =  97
    # RADIUS Attribute EAP Key name
    EAPKEYNAME           = 102
    # RADIUS Attribute Operator Name
    # Used to generate the Chargeable User Identity
    OPERATORNAME         = 126
    # RADIUS Attribute Location Information
    LOCATIONINFORMATION  = 127
    # RADIUS Attribute Location Data
    LOCATIONDATA         = 128
    # RADIUS Attribute Location Capable
    LOCATIONCAPABLE      = 131
    # RADIUS Attribute Mobility Domain ID
    MOBILITYDOMAINID     = 177
    # RADIUS Attribute WLAN Pairwise Cipher
    WLANPAIRWISECIPHER   = 186
    # RADIUS Attribute WLAN Group Cipher
    WLANGROUPCIPHER      = 187
    # RADIUS Attribute WLAN AKM Suite
    WLANAKMSUITE         = 188
    # RADIUS Attribute WLAN Group Management Cipher
    WLANGROUPMGMTCIPHER  = 189
    # RADIUS Attribute WLAN RF Band
    WLANRFBAND           = 190

    # Get Attribute name by the given code
    # @param code [Byte] Code of the Attribute
    # @return [String] Name of the Attribute, or "UNKNOWN_ATTRIBUTE_<num>" if Attribute is unknown.
    def self.get_attribute_name_by_code(code)
      return nil if code.nil?

      Attribute.constants.each do |const|
        next if Attribute.const_get(const) != code

        return const.to_s
      end
      "UNKNOWN_ATTRIBUTE_#{code}"
    end
  end

  attr_reader :packetfu_pkt, :raw_data, :packettype, :identifier, :length, :authenticator, :attributes, :eap,
              :udp, :state, :username, :callingstationid, :realm, :eapdetails

  def initialize(pkt)
    raise PacketLengthNotValidError, 'Length of packet violates RFC2865' if pkt.udp_len < 20

    # Save UDP Header information (needed for matching packets
    @udp = { src: { ip: pkt.ip_saddr, port: pkt.udp_sport }, dst: { ip: pkt.ip_daddr, port: pkt.udp_dport } }
    @other_src_info = nil

    @raw_data = pkt.payload.unpack('C*')
    @packetfu_pkt = pkt

    # Parse Radius Headers
    @packettype = @raw_data[0]
    @identifier = @raw_data[1]
    @length = @raw_data[2] * 256 + @raw_data[3]

    # This case should actually not happen, but it happened. (I hate IP fragmentation)
    if @length != @raw_data.length
      raise PacketLengthNotValidError, "Raw data length #{@raw_data.length} does not match identified length #{@length}"
    end

    @authenticator = @raw_data[4..19]

    @attributes = []
    @attributes_by_type = {}
    @state = nil
    @username = nil
    @callingstationid = nil
    @realm = nil


    @attributes_by_type[RadiusPacket::Attribute::USERNAME] ||= []
    @attributes_by_type[RadiusPacket::Attribute::STATE] ||= []
    @attributes_by_type[RadiusPacket::Attribute::CALLINGSTATIONID] ||= []

    cur_ptr = 20
    while cur_ptr < @length
      attribute = {}
      attribute[:type] = @raw_data[cur_ptr]
      attribute[:length] = @raw_data[cur_ptr + 1]
      attribute[:data] = @raw_data[cur_ptr + 2..cur_ptr + attribute[:length] - 1]
      @attributes << attribute
      @attributes_by_type[attribute[:type]] ||= []
      @attributes_by_type[attribute[:type]] << attribute
      cur_ptr += attribute[:length]
      @state ||= attribute[:data] if attribute[:type] == RadiusPacket::Attribute::STATE
      if attribute[:type] == RadiusPacket::Attribute::USERNAME
        @username ||= attribute[:data]
        unless @username.nil?
          parts = @username.pack('C*').split('@')
          @realm ||= 'NONE' if parts.length == 1
          @realm ||= parts.last
        end
      end
      @callingstationid ||= attribute[:data] if attribute[:type] == RadiusPacket::Attribute::CALLINGSTATIONID
    end

    parse_eap
  end

  # Convert Attributes to Hex string
  # @param attrs [Array] Array of attributes as byte arrays
  # @return [String] Hex value of attributes, separated by ' - ' if more then one.
  def attr_to_hex(attrs)
    attrs.map { |x| x[:data].pack('C*').unpack1('H*') }.join(' - ')
  end

  # Convert Attributes to normal string (escaped by inspect)
  # @param attrs [Array] Array of attributes as byte arrays
  # @return [String] String value of attributes, separated by ' - ' if more then one
  def attr_to_string(attrs)
    attrs.map { |x| x[:data].pack('C*').inspect }.join(' - ')
  end

  private :attr_to_hex, :attr_to_string

  # Checks if the RADIUS Packet is a status server packet
  # @return [TrueClass,FalseClass] true if StatusServer, false otherwise
  def status_server?
    @packettype == RadiusPacket::Type::STATUS_SERVER
  end

  # Reassembles the EAP messages by concatenating the contents of all EAP-Message attributes.
  def parse_eap
    @attributes.each do |a|
      next unless a[:type] == RadiusPacket::Attribute::EAPMESSAGE

      @eap ||= []
      @eap += a[:data]
    end
  end

  # Parses the EAP message contained in the RADIUS message to check for illegal EAP messages
  # @raise PreliminaryEAPParsingError
  def parse_eap!
    return unless @eap && !@eap.empty?

    @eapdetails = {}
    @eapdetails[:code] = @eap[0] if @eap[0]
    @eapdetails[:encoded_length] = @eap[2] * 256 + @eap[3] if @eap[2] && @eap[3]
    @eapdetails[:type] = @eap[4] if @eap[4]

    @eapdetails[:actual_length] = @eap.length
    # rubocop:disable Style/GuardClause
    # rubocop:disable Style/NumericPredicate
    # rubocop:disable Style/IfUnlessModifier
    if @eapdetails[:code] == 0 || @eapdetails[:code] > 5
      raise PreliminaryEAPParsingError, "Seen invalid EAP code: #{@eapdetails[:code]}"
    end

    if @eapdetails[:encoded_length] != @eapdetails[:actual_length]
      raise PreliminaryEAPParsingError, "Encoded Length (#{@eapdetails[:encoded_length]}) did not match actual length (#{@eapdetails[:actual_length]})"
    end
    # rubocop:enable Style/GuardClause
    # rubocop:enable Style/NumericPredicate
    # rubocop:enable Style/IfUnlessModifier
  end
end

