package enet

VERSION_MAJOR :: u8(1)
VERSION_MINOR :: u8(3)
VERSION_PATCH :: u8(17)

version_create :: #force_inline proc(major, minor, patch: u8) -> u32
{
	return (u32(major) << 16) | (u32(minor) << 8) | u32(patch)
}

version_get_major :: #force_inline proc(version: u32) -> u8
{
	return u8((version >> 16) & 0xff)
}

version_get_minor :: #force_inline proc(version: u32) -> u8
{
	return u8((version >> 8) & 0xff)
}

version_get_patch :: #force_inline proc(version: u32) -> u8
{
	return u8(version & 0xff)
}

// Odin does not have "macros" or compile-time evaluation of functions, so the
// following is just the same as.
// VERSION :: VERSION_CREATE(VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH);
VERSION :: (u32(VERSION_MAJOR) << 16) | (u32(VERSION_MINOR) << 8) | u32(VERSION_PATCH)

// Network byte order is always Big Endian. Instead of using the method ENet
// uses (leveraging {n,h}to{n,h}{s,l}), we can just use Odin's endianess types
// to get the correct byte swaps, if any.
host_to_net_16 :: #force_inline proc(value: u16) -> u16
{
	return transmute(u16)u16be(value)
}

host_to_net_32 :: #force_inline proc(value: u32) -> u32
{
	return transmute(u32)u32be(value)
}

net_to_host_16 :: #force_inline proc(value: u16) -> u16
{
	return u16(transmute(u16be)value)
}

net_to_host_32 :: #force_inline proc(value: u32) -> u32
{
	return u32(transmute(u32be)value)
}

Version :: u32

Socket_Type :: enum i32
{
	Stream   = 1,
	Datagram = 2,
}

Socket_Wait :: enum i32
{
	None      = 0,
	Send      = 1 << 0,
	Receive   = 1 << 1,
	Interrupt = 1 << 2,
}

Socket_Option :: enum i32
{
	Non_Block  = 1,
	Broadcast = 2,
	Rcv_Buf    = 3,
	Snd_Buf    = 4,
	Reuse_Addr = 5,
	Rcv_Time_O  = 6,
	Snd_Time_O  = 7,
	Error     = 8,
	No_Delay   = 9,
}

Socket_Shutdown :: enum i32
{
	Read       = 0,
	Write      = 1,
	Read_Write = 2,
}

HOST_ANY       :: 0
HOST_BROADCAST :: 0xffffffff
PORT_ANY       :: 0

Address :: struct
{
	host: u32,
	port: u16,
}

Packet_Flags :: bit_set[Packet_Flag; i32]

Packet_Flag :: enum i32
{
	Reliable            = 0,
	Unsequenced         = 1,
	No_Allocate         = 2,
	Unreliable_Fragment = 3,
	Flag_Sent           = 8,
}

Packet_Free_Callback :: proc "c" (packet: ^Packet)

Packet :: struct
{
	reference_count: u64,
	flags:           Packet_Flags,
	data:            [^]u8,
	data_length:     u64,
	free_callback:   Packet_Free_Callback,
	user_data:       rawptr,
}

Acknowledgment :: struct
{
	acknowledgement_list: List_Node,
	sent_time:            u32,
	command:              Protocol,
}

Outgoing_Command :: struct
{
	outgoing_command_list:      List_Node,
	reliable_sequence_number:   u16,
	unreliable_sequence_number: u16,
	sent_time:                  u32,
	round_trip_timeout:         u32,
	round_trip_timeout_limit:   u32,
	fragment_offset:            u32,
	fragment_length:            u16,
	send_attempts:              u16,
	command:                  	Protocol,
	packet:                   	^Packet,
}

Incoming_Command :: struct
{
	incoming_command_list:      List_Node,
	reliable_sequence_number:   u16,
	unreliable_sequence_number: u16,
	command:                    Protocol,
	fragment_count:            	u32,
	fragments_remaining:       	u32,
	fragments:                	[^]u32,
	packet:                   	^Packet,
}

Peer_State :: enum i32
{
	Disconnected,
	Connecting,
	Acknowledging_Connect,
	Connection_Pending,
	Connection_Succeeded,
	Connected,
	Disconnect_Later,
	Disconnecting,
	Acknowledging_Disconnect,
	Zombie,
}

BUFFER_MAXIMUM                    :: (1 + 2 * PROTOCOL_MAXIMUM_PACKET_COMMANDS)

HOST_RECEIVE_BUFFER_SIZE          :: 256 * 1024
HOST_SEND_BUFFER_SIZE             :: 256 * 1024
HOST_BANDWIDTH_THROTTLE_INTERVAL  :: 1000
HOST_DEFAULT_MTU                  :: 1400
HOST_DEFAULT_MAXIMUM_PACKET_SIZE  :: 32 * 1024 * 1024
HOST_DEFAULT_MAXIMUM_WAITING_DATA :: 32 * 1024 * 1024

PEER_DEFAULT_ROUND_TRIP_TIME      :: 500
PEER_DEFAULT_PACKET_THROTTLE      :: 32
PEER_PACKET_THROTTLE_SCALE        :: 32
PEER_PACKET_THROTTLE_COUNTER      :: 7
PEER_PACKET_THROTTLE_ACCELERATION :: 2
PEER_PACKET_THROTTLE_DECELERATION :: 2
PEER_PACKET_THROTTLE_INTERVAL     :: 5000
PEER_PACKET_LOSS_SCALE            :: 1 << 16
PEER_PACKET_LOSS_INTERVAL         :: 10000
PEER_WINDOW_SIZE_SCALE            :: 64 * 1024
PEER_TIMEOUT_LIMIT                :: 32
PEER_TIMEOUT_MINIMUM              :: 5000
PEER_TIMEOUT_MAXIMUM              :: 30000
PEER_PING_INTERVAL                :: 500
PEER_UNSEQUENCED_WINDOWS          :: 64
PEER_UNSEQUENCED_WINDOW_SIZE      :: 1024
PEER_FREE_UNSEQUENCED_WINDOWS     :: 32
PEER_RELIABLE_WINDOWS             :: 16
PEER_RELIABLE_WINDOW_SIZE         :: 0x1000
PEER_FREE_RELIABLE_WINDOWS        :: 8

Channel :: struct
{
	outgoing_reliable_sequence_number:   u16,
	outgoing_unreliable_sequence_number: u16,
	used_reliable_windows:               u16,
	reliable_windows:                    [PEER_RELIABLE_WINDOWS]u16,
	incoming_reliable_sequence_number:   u16,
	incoming_unreliable_sequence_number: u16,
	incoming_reliable_commands:          List,
	incoming_unreliable_commands:        List,
}

Peer_Flag :: enum i32
{
	Needs_Dispatch,
}

Peer :: struct
{
	dispatch_list:                   List_Node,
	host:                           ^Host,
	outgoing_peer_id:                 u16,
	incoming_peer_id:                 u16,
	connect_id:                      u32,
	outgoing_session_id:              u8,
	incoming_session_id:              u8,
	address:                        Address,
	data:                           rawptr,
	state:                          Peer_State,
	channels:                       [^]Channel,
	channel_count:                   u64,
	incoming_bandwidth:              u32,
	outgoing_bandwidth:              u32,
	incoming_bandwidth_throttle_epoch: u32,
	outgoing_bandwidth_throttle_epoch: u32,
	incoming_data_total:              u32,
	outgoing_data_total:              u32,
	last_send_time:                   u32,
	last_receive_time:                u32,
	next_timeout:                    u32,
	earliest_timeout:                u32,
	packet_loss_epoch:                u32,
	packets_sent:                    u32,
	packets_lost:                    u32,
	packet_loss:                     u32,
	packet_loss_variance:             u32,
	packet_throttle:                 u32,
	packet_throttle_limit:            u32,
	packet_throttle_counter:          u32,
	packet_throttle_epoch:            u32,
	packet_throttle_acceleration:     u32,
	packet_throttle_deceleration:     u32,
	packet_throttle_interval:         u32,
	ping_interval:                   u32,
	timeout_limit:                   u32,
	timeout_minimum:                 u32,
	timeout_maximum:                 u32,
	last_round_trip_time:              u32,
	lowest_round_trip_time:            u32,
	last_round_trip_time_variance:      u32,
	highest_round_trip_time_variance:   u32,
	round_trip_time:                  u32,
	round_trip_time_variance:          u32,
	mtu:                            u32,
	window_size:                     u32,
	reliable_data_in_transit:          u32,
	outgoing_reliable_sequence_number: u16,
	acknowledgements:               List,
	sent_reliable_commands:           List,
	sent_unreliable_commands:         List,
	outgoing_commands:               List,
	dispatched_commands:             List,
	flags:                          u16,
	reserved:                       u16,
	incoming_unsequenced_group:       u16,
	outgoing_unsequenced_group:       u16,
	unsequenced_window:              [PEER_UNSEQUENCED_WINDOW_SIZE / 32]u32,
	event_data:                      u32,
	total_waiting_data:               u64,
}

Compressor :: struct
{
	context_:   rawptr,
	compress:   proc "c" (context_: rawptr, in_buffers: [^]Buffer, in_buffer_count: u64, in_limit: u64, out_data: [^]u8, out_limit: u64) -> u64,
	decompress: proc "c" (context_: rawptr, in_data: [^]u8, in_limit: u64, out_data: [^]u8, out_limit: u64) -> u64,
	destroy:    proc "c" (context_: rawptr),
}

Checksum_Callback  :: proc "c" (buffers: [^]Buffer, buffer_count: u64) -> u32
Intercept_Callback :: proc "c" (host: ^Host, event: ^Event) -> i32

Host :: struct
{
	socket:                     Socket,
	address:                    Address,
	incoming_bandwidth:          u32,
	outgoing_bandwidth:          u32,
	bandwidth_throttle_epoch:     u32,
	mtu:                        u32,
	random_seed:                 u32,
	recalculate_bandwidth_limits: i32,
	peers:                      [^]Peer,
	peer_count:                  u64,
	channel_limit:               u64,
	service_time:                u32,
	dispatch_queue:              List,
	continue_sending:            i32,
	packet_size:                 u64,
	header_flags:                u16,
	commands:                   [PROTOCOL_MAXIMUM_PACKET_COMMANDS]Protocol,
	command_count:               u64,
	buffers:                    [BUFFER_MAXIMUM]Buffer,
	buffer_count:                u64,
	checksum:                   Checksum_Callback,
	compressor:                 Compressor,
	packet_data:                 [2][PROTOCOL_MAXIMUM_MTU]u8,
	received_address:            Address,
	received_data:               [^]u8,
	received_data_length:         u64,
	total_sent_data:              u32,
	total_sent_packets:           u32,
	total_received_data:          u32,
	total_received_packets:       u32,
	intercept:                  Intercept_Callback,
	connected_peers:             u64,
	bandwidth_limited_peers:      u64,
	duplicate_peers:             u64,
	maximum_packet_size:          u64,
	maximum_waiting_data:         u64,
}

Event_Type :: enum i32
{
	None       = 0,
	Connect    = 1,
	Disconnect = 2,
	Receive    = 3,
}

Event :: struct
{
	type:      Event_Type,
	peer:      ^Peer,
	channel_id: u8,
	data:      u32,
	packet:    ^Packet,
}

Callbacks :: struct
{
	malloc:    proc "c" (size: uint) -> rawptr,
	free:      proc "c" (memory: rawptr),
	no_memory: proc "c" (),
}

List_Node :: struct
{
	next:     ^List_Node,
	previous: ^List_Node,
}

List :: struct
{
	sentinel: List_Node,
}

PROTOCOL_MINIMUM_MTU             :: 576
PROTOCOL_MAXIMUM_MTU             :: 4096
PROTOCOL_MAXIMUM_PACKET_COMMANDS :: 32
PROTOCOL_MINIMUM_WINDOW_SIZE     :: 4096
PROTOCOL_MAXIMUM_WINDOW_SIZE     :: 65536
PROTOCOL_MINIMUM_CHANNEL_COUNT   :: 1
PROTOCOL_MAXIMUM_CHANNEL_COUNT   :: 255
PROTOCOL_MAXIMUM_PEER_ID         :: 0xFFF
PROTOCOL_MAXIMUM_FRAGMENT_COUNT  :: 1024 * 1024

Protocol_Command :: enum i32
{
	None                     = 0,
	Acknowledge              = 1,
	Connect                  = 2,
	Verify_Connect           = 3,
	Disconnect               = 4,
	Ping                     = 5,
	Send_Reliable            = 6,
	Send_Unreliable          = 7,
	Send_Fragment            = 8,
	Send_Unsequenced         = 9,
	Bandwidth_Limit          = 10,
	Throttle_Configure       = 11,
	Send_Unreliable_Fragment = 12,
	Count                    = 13,
	Mask                     = 0x0F,
}

Protocol_Flag :: enum i32
{
	Command_Acknowledge    = 1 << 7,
	Command_Unsequenced    = 1 << 6,
	Header_Compressed      = 1 << 14,
	Header_Sent_Time       = 1 << 15,
	Header_Mask            = Header_Compressed | Header_Sent_Time,
	Header_Session_Mask    = 3 << 12,
	Header_Session_Shift   = 12,
}

Protocol_Header :: struct #packed
{
	peer_id:   u16,
	sent_time: u16,
}

Protocol_Command_Header :: struct #packed
{
	command:                u8,
	channel_id:              u8,
	reliable_sequence_number: u16,
}

Protocol_Acknowledge :: struct #packed
{
	header:                     Protocol_Command_Header,
	outgoing_peer_id:             u16,
	incoming_session_id:          u8,
	outgoing_session_id:          u8,
	mtu:                        u32,
	window_size:                 u32,
	channel_count:               u32,
	incoming_bandwidth:          u32,
	outgoing_bandwidth:          u32,
	packet_throttle_interval:     u32,
	packet_throttle_acceleration: u32,
	packet_throttle_deceleration: u32,
	connect_id:                  u32,
	data:                       u32,
}

Protocol_Connect :: struct #packed
{
	header:                     Protocol_Command_Header,
	outgoing_peer_id:             u16,
	incoming_session_id:          u8,
	outgoing_session_id:          u8,
	mtu:                        u32,
	window_size:                 u32,
	channel_count:               u32,
	incoming_bandwidth:          u32,
	outgoing_bandwidth:          u32,
	packet_throttle_interval:     u32,
	packet_throttle_acceleration: u32,
	packet_throttle_deceleration: u32,
	connect_id:                  u32,
	data:                       u32,
}

Protocol_Verify_Connect :: struct #packed
{
	header:                      Protocol_Command_Header,
	outgoing_peer_id:              u16,
	incoming_session_id:           u8,
	outgoing_session_id:           u8,
	mtu:                         u32,
	window_size:                  u32,
	channel_count:                u32,
	incoming_bandwidth:           u32,
	outgoing_bandwidth:           u32,
	packet_throttle_interval:      u32,
	packet_throttle_acceleration:  u32,
	packet_throttle_deceleration:  u32,
	connect_id:                   u32,
}

Protocol_Bandwidth_Limit :: struct #packed
{
	header:            Protocol_Command_Header,
	incoming_bandwidth: u32,
	outgoing_bandwidth: u32,
}

Protocol_Throttle_Configure :: struct #packed
{
	header:                     Protocol_Command_Header,
	packet_throttle_interval:     u32,
	packet_throttle_acceleration: u32,
	packet_throttle_deceleration: u32,
}

Protocol_Disconnect :: struct #packed
{
	header: Protocol_Command_Header,
	data:   u32,
}

Protocol_Ping :: struct #packed
{
	header: Protocol_Command_Header,
}

Protocol_Send_Reliable :: struct #packed
{
	header:     Protocol_Command_Header,
	dataLength: u16,
}

Protocol_Send_Unreliable :: struct #packed {
	header:                   Protocol_Command_Header,
	unreliable_sequence_number: u16,
	data_length:               u16,
}

Protocol_Send_Unsequenced :: struct #packed {
	header:           Protocol_Command_Header,
	unsequenced_group: u16,
	data_length:       u16,
}

Protocol_Send_Fragment :: struct #packed {
	header:              Protocol_Command_Header,
	start_sequence_number: u16,
	data_length:          u16,
	fragment_count:       u32,
	fragment_number:      u32,
	total_length:         u32,
	fragment_offset:      u32,
}

Protocol :: struct #raw_union {
	header:            Protocol_Command_Header,
	acknowledge:       Protocol_Acknowledge,
	connect:           Protocol_Connect,
	verify_connect:     Protocol_Verify_Connect,
	disconnect:        Protocol_Disconnect,
	ping:              Protocol_Ping,
	send_reliable:      Protocol_Send_Reliable,
	send_unreliable:    Protocol_Send_Unreliable,
	send_unsequenced:   Protocol_Send_Unsequenced,
	send_fragment:      Protocol_Send_Fragment,
	bandwidth_limit:    Protocol_Bandwidth_Limit,
	throttle_configure: Protocol_Throttle_Configure,
}

TIME_OVERFLOW :: u32(86400000)

time_less :: #force_inline proc(a, b: u32) -> bool
{
	return a - b >= TIME_OVERFLOW
}

time_greater :: #force_inline proc(a, b: u32) -> bool
{
	return b - a >= TIME_OVERFLOW
}

time_less_equal :: #force_inline proc(a, b: u32) -> bool
{
	return !time_greater(a, b)
}

time_greater_equal :: #force_inline proc(a, b: u32) -> bool
{
	return time_less(a, b)
}

time_difference :: #force_inline proc(a, b: u32) -> u32
{
	return a - b >= TIME_OVERFLOW ? b - a : a - b
}

when ODIN_OS == .Linux do Socket :: u32
when ODIN_OS == .Windows do Socket :: u64

when ODIN_OS == .Windows
{
	Socket_Set :: struct
	{
		fd_count: u32,
		fd_array: [64]Socket,
	}
}

when ODIN_OS == .Linux
{
	Socket_Set :: struct
	{
		fds_bits: [64 / 8 / size_of(u64)]u64,
	}
}

Buffer :: struct
{
	data:       rawptr,
	dataLength: uint,
}

when ODIN_OS == .Windows && ODIN_ARCH == .amd64
{
	foreign import enet {
		"binaries/enet_windows_amd64.lib",
		"system:ws2_32.lib",
		"system:winmm.lib",
	}
}

@(default_calling_convention="c", link_prefix="enet_")
foreign enet
{
	initialize                     :: proc() -> i32 ---
	initialize_with_callbacks      :: proc(version: Version, inits: ^Callbacks) -> i32 ---
	deinitialize                   :: proc() ---
	linked_version                 :: proc() -> Version ---
	time_get                       :: proc() -> u32 ---
	time_set                       :: proc(new_time_base: u32) ---

	socket_create                  :: proc(Socket_Type) -> Socket ---
	socket_bind                    :: proc(socket: Socket, address: ^Address) -> i32 ---
	socket_get_address             :: proc(socket: Socket, address: ^Address) -> i32 ---
	socket_listen                  :: proc(socket: Socket, backlog: i32) -> i32 ---
	socket_accept                  :: proc(socket: Socket, address: ^Address) -> Socket ---
	socket_connect                 :: proc(socket: Socket, address: ^Address) -> i32 ---
	socket_send                    :: proc(socket: Socket, address: ^Address, buffers: [^]Buffer, buffer_count: u64) -> i32 ---
	socket_receive                 :: proc(socket: Socket, address: ^Address, buffers: [^]Buffer, buffer_count: u64) -> i32 ---
	socket_wait                    :: proc(socket: Socket, condition: ^u32, timeout: u32) -> i32 ---
	socket_set_option              :: proc(socket: Socket, option: Socket_Option, value: i32) -> i32 ---
	socket_get_option              :: proc(socket: Socket, option: Socket_Option, value: ^i32) -> i32 ---
	socket_shutdown                :: proc(socket: Socket, how: Socket_Shutdown) -> i32 ---
	socket_destroy                 :: proc(socket: Socket) ---
	socketset_select               :: proc(socket: Socket, read_set: ^Socket_Set, write_set: ^Socket_Set, timeout: u32) -> i32 ---

	address_set_host_ip            :: proc(address: ^Address, host_name: cstring) -> i32 ---
	address_set_host               :: proc(address: ^Address, host_name: cstring) -> i32 ---
	address_get_host_ip            :: proc(address: ^Address, host_name: [^]u8, name_length: u64) -> i32 ---
	address_get_host               :: proc(address: ^Address, host_name: [^]u8, name_length: u64) -> i32 ---

	packet_create                  :: proc(data: rawptr, data_length: u64, flags: Packet_Flags) -> ^Packet ---
	packet_destroy                 :: proc(packet: ^Packet) ---
	packet_resize                  :: proc(packet: ^Packet, data_length: u64) -> i32 ---
	crc32                          :: proc(buffers: [^]Buffer, buffer_count: u64) -> u32 ---

	host_create                    :: proc(address: ^Address, peer_count: u64, channel_limit: u64, incoming_bandwidth: u32, outgoing_bandwidth: u32) -> ^Host ---
	host_destroy                   :: proc(host: ^Host) ---
	host_connect                   :: proc(host: ^Host, address: ^Address, channel_count: u64, data: u32) -> ^Peer ---
	host_check_events              :: proc(host: ^Host, event: ^Event) -> i32 ---
	host_service                   :: proc(host: ^Host, event: ^Event, timeout: u32) -> i32 ---
	host_flush                     :: proc(host: ^Host) ---
	host_broadcast                 :: proc(host: ^Host, channel_id: u8, packet: ^Packet) ---
	host_compress                  :: proc(host: ^Host, compressor: ^Compressor) ---
	host_compress_with_range_coder :: proc(host: ^Host) -> i32 ---
	host_channel_limit             :: proc(host: ^Host, channel_limit: u64) ---
	host_bandwidth_limit           :: proc(host: ^Host, incoming_bandwidth: u32, outgoing_bandwidth: u32) ---

	peer_send                      :: proc(peer: ^Peer, channel_id: u8, packet: ^Packet) -> i32 ---
	peer_receive                   :: proc(peer: ^Peer, channel_id: ^u8) -> ^Packet ---
	peer_ping                      :: proc(peer: ^Peer) ---
	peer_ping_interval             :: proc(peer: ^Peer, ping_interval: u32) ---
	peer_timeout                   :: proc(peer: ^Peer, timout_limit: u32, timeout_minimum: u32, timeout_maximum: u32) ---
	peer_reset                     :: proc(peer: ^Peer) ---
	peer_disconnect                :: proc(peer: ^Peer, data: u32) ---
	peer_disconnect_now            :: proc(peer: ^Peer, data: u32) ---
	peer_disconnect_later          :: proc(peer: ^Peer, data: u32) ---
	peer_throttle_configure        :: proc(peer: ^Peer, interval: u32, acceleration: u32, deceleration: u32) ---

	range_coder_create             :: proc() -> rawptr ---
	range_coder_destroy            :: proc(ctx: rawptr) ---
	range_coder_compress           :: proc(ctx: rawptr, in_buffers: [^]Buffer, in_buffer_count: u64, in_limit: u64, out_data: [^]u8, out_limit: u64) -> u64 ---
	range_coder_decompress         :: proc(ctx: rawptr, in_data: [^]u8, in_limit: u64, out_data: [^]u8, out_limit: u64) -> u64 ---
}