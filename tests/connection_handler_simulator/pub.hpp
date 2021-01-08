#pragma once

#include <arataga/config.hpp>

#include <asio/ip/tcp.hpp>

#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace connection_handler_simulator
{

struct handler_config_values_t
{
	::arataga::acl_protocol_t m_acl_protocol{
			::arataga::acl_protocol_t::autodetect
		};
	asio::ip::address m_out_addr{ asio::ip::make_address( "127.0.0.1" ) };
	std::size_t m_io_chunk_size{ 1024u };
	std::chrono::milliseconds m_protocol_detection_timeout{ 500 };
	std::chrono::milliseconds m_socks_handshake_phase_timeout{ 1'000 };
	std::chrono::milliseconds m_dns_resolving_timeout{ 500 };
	std::chrono::milliseconds m_authentification_timeout{ 500 };
	std::chrono::milliseconds m_connect_target_timeout{ 500 };
	std::chrono::milliseconds m_socks_bind_timeout{ 1'500 };
	std::chrono::milliseconds m_idle_connection_timeout{ 1'500 };
	std::chrono::milliseconds m_http_headers_complete_timeout{ 1'000 };
	std::chrono::milliseconds m_http_negative_response_timeout{ 1'000 };

	::arataga::http_message_value_limits_t m_http_message_limits{};
};

inline void
dump_trace(
	std::ostream & to,
	const std::vector< std::string > & trace )
{
	for( const auto & v : trace )
		to << v << std::endl;
}

class simulator_t
{
public:
	simulator_t(
		asio::ip::tcp::endpoint entry_point,
		handler_config_values_t config_values );
	~simulator_t();

	[[nodiscard]]
	std::vector< std::string >
	get_trace();

private:
	struct internals_t;

	std::unique_ptr< internals_t > m_impl;
};

} /* namespace connection_handler_simulator */

