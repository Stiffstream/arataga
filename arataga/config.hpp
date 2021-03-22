/*!
 * @file
 * @brief Stuff for working with configuration.
 */

#pragma once

#include <arataga/exception.hpp>

#include <arataga/bandlim_config.hpp>

#include <spdlog/spdlog.h>

#include <asio/ip/address.hpp>

#include <algorithm>
#include <chrono>
#include <memory>
#include <ostream>
#include <string_view>
#include <tuple>
#include <variant>

namespace arataga
{

//
// denied_ports_config_t
//
/*!
 * @brief Config for denied TCP-ports.
 */
struct denied_ports_config_t
{
	//! Type for holding port number.
	using port_t = std::uint16_t;

	//! A case when a single port is blocked.
	struct single_port_case_t
	{
		port_t m_port;

		// For debugging purposes only.
		[[nodiscard]]
		bool
		operator==( const single_port_case_t & b ) const noexcept
		{
			return this->m_port == b.m_port;
		}
	};

	//! A case when a range of ports is blocked.
	/*!
	 * Holds a range in the form [low, high].
	 */
	struct ports_range_case_t
	{
		port_t m_low;
		port_t m_high;

		// For debugging purposes only.
		[[nodiscard]]
		bool
		operator==( const ports_range_case_t & b ) const noexcept
		{
			return this->m_low == b.m_low && this->m_high == b.m_high;
		}
	};

	//! Description of a single case.
	using denied_case_t = std::variant<
			single_port_case_t, ports_range_case_t >;

	//! Type of storage for several cases.
	using case_container_t = std::vector< denied_case_t >;

	//! Description of denied ports.
	/*!
	 * This container can be empty. It means that client can connect
	 * to any port.
	 */
	case_container_t m_cases;

	//! Helper function for checking is specified port denied or not.
	[[nodiscard]]
	bool
	is_denied( port_t port ) const noexcept
	{
		struct checker_t {
			port_t m_port;

			bool
			operator()( const single_port_case_t & c ) const noexcept
			{
				return c.m_port == m_port;
			}

			bool
			operator()( const ports_range_case_t & c ) const noexcept
			{
				return c.m_low <= m_port && m_port <= c.m_high;
			}
		};

		return std::any_of( m_cases.begin(), m_cases.end(),
				[port]( const auto & c ) noexcept {
					return std::visit( checker_t{ port }, c );
				} );
	}
};

//
// acl_protocol_t
//
/*!
 * @brief Type of protocol to be used by an ACL (http, socks, etc).
 */
enum class acl_protocol_t
{
	//! ACL should detect the protocol automatically.
	autodetect,
	//! ACL should use SOCKS only.
	socks,
	//! ACL should use HTTP only.
	http
};

// For debugging purposes only.
std::ostream &
operator<<( std::ostream & to, acl_protocol_t proto );

//
// acl_config_t
//
/*!
 * @brief Config for a single ACL.
 */
struct acl_config_t
{
	//! Type for TCP-port.
	using port_t = std::uint16_t;

	//! The protocol for that ACL.
	acl_protocol_t m_protocol;

	//! TCP-port for that ACL.
	/*!
	 * The ACL opens an incoming socket on that port and accepts new
	 * connections from clients on that port.
	 */
	port_t m_port;

	//! IP-address for incoming connections to that ACL.
	/*!
	 * The ACL opens an incoming socket on that address.
	 * Clients will use that address to connect to arataga.
	 *
	 * Only IPv4 addresses are supported now.
	 */
	asio::ip::address_v4 m_in_addr;

	//! IP-address for outgoing connections by that ACL.
	/*!
	 * The ACL will use this address for outgoing connections to target
	 * hosts during serving client's requests.
	 */
	asio::ip::address m_out_addr;

	//! Initializing constructor.
	acl_config_t(
		acl_protocol_t protocol,
		port_t port,
		asio::ip::address_v4 in_addr,
		asio::ip::address out_addr )
		:	m_protocol{ protocol }
		,	m_port{ port }
		,	m_in_addr{ std::move(in_addr) }
		,	m_out_addr{ std::move(out_addr) }
	{}

	// For debugging purposes only.
	[[nodiscard]]
	bool
	operator==( const acl_config_t & b ) const noexcept
	{
		const auto tup = []( const auto & v ) {
			return std::tie( v.m_protocol, v.m_port,
					v.m_in_addr, v.m_out_addr );
		};
		return tup( *this ) == tup( b );
	}
};

// For debugging purposes only.
std::ostream &
operator<<( std::ostream & to, const acl_config_t & acl );

//
// http_message_value_limits_t
//
/*!
 * @brief Set of constraints for elements of HTTP protocol.
 */
struct http_message_value_limits_t
{
	//! Length of request-target in start-line of HTTP-request.
	std::size_t m_max_request_target_length{ 8u*1024u };
	//! Length of HTTP-field name.
	std::size_t m_max_field_name_length{ 2u*1024u };
	//! Length of HTTP-field value.
	std::size_t m_max_field_value_length{ 10u*1024u };
	//! Total size of all HTTP-fields.
	std::size_t m_max_total_headers_size{ 80u*1024u };
	//! Length of status-line of HTTP-response.
	std::size_t m_max_status_line_length{ 1u*1024u };
};

//
// common_acl_params_t
//
/*!
 * @brief Set of common for all ACL parameters.
 */
struct common_acl_params_t
{
	/*!
	 * @brief The max count of parallel active connections to one ACL.
	 */
	unsigned int m_maxconn{ 100u };

	/*!
	 * @brief The default band-limits for a client.
	 *
	 * Those constraits are applied if there is no personal limits
	 * for a client.
	 */
	bandlim_config_t m_client_bandlim;

	/*!
	 * @brief Time-out before sending negative authentification response.
	 */
	std::chrono::milliseconds m_failed_auth_reply_timeout{ 750 };

	/*!
	 * @name Various time-outs used during handling of client connections.
	 * @{
	 */
	std::chrono::milliseconds m_protocol_detection_timeout{ 3'000 };
	std::chrono::milliseconds m_socks_handshake_phase_timeout{ 5'000 };
	std::chrono::milliseconds m_dns_resolving_timeout{ 4'000 };
	std::chrono::milliseconds m_authentification_timeout{ 1'500 };
	std::chrono::milliseconds m_connect_target_timeout{ 5'000 };
	std::chrono::milliseconds m_socks_bind_timeout{ 20'000 };
	std::chrono::milliseconds m_idle_connection_timeout{ 300'000 };
	std::chrono::milliseconds m_http_headers_complete_timeout{ 5'000 };
	std::chrono::milliseconds m_http_negative_response_timeout{ 2'000 };
	/*!
	 * @}
	 */

	/*!
	 * @brief The size of one buffer for I/O ops.
	 *
	 * This size is used for accepted connections for those handshaking
	 * and authentification are completed. During the handshaking
	 * buffers of different sizes could be used.
	 */
	std::size_t m_io_chunk_size{ 8u * 1024u };

	/*!
	 * @brief Max count of buffers for I/O ops on single connection.
	 *
	 * Since v.0.2.0 several buffers can be used for I/O operations
	 * for data transfer. While one buffer is used for reading another
	 * buffer can be used for writting.
	 *
	 * This parameters sets number of buffers to be used for a single
	 * connection.
	 *
	 * Please note that arataga uses one connection from a client to an ACL
	 * and another connection from the ACL to the target host. It means
	 * that there will be 2*m_io_chunk_count buffers (becasue every
	 * connection uses own set of buffers).
	 *
	 * @since v.0.2.0
	 */
	std::size_t m_io_chunk_count{ 4u };

	/*!
	 * @brief Constraints for values of HTTP-protocols.
	 */
	http_message_value_limits_t m_http_message_limits{};
};

/*!
 * @brief Configuration for the whole arataga.
 */
struct config_t
{
	/*!
	 * @brief Log level to be used for logging.
	 *
	 * The value spdlog::level::off means that logging should
	 * be disabled.
	 */
	spdlog::level::level_enum m_log_level{ spdlog::level::info };

	/*!
	 * @brief Clearing period for DNS cache.
	 */
	std::chrono::milliseconds m_dns_cache_cleanup_period{ 30*1000 };

	/*!
	 * @brief Denied TCP-ports.
	 *
	 * Clients can't use those ports on target hosts.
	 */
	denied_ports_config_t m_denied_ports;

	/*!
	 * @brief Common parameters for all ACL.
	 */
	common_acl_params_t m_common_acl_params;

	/*!
	 * @brief Type of storage for ACL configs.
	 */
	using acl_container_t = std::vector< acl_config_t >;

	/*!
	 * @brief List of ACL.
	 *
	 * Can be empty.
	 */
	acl_container_t m_acls;
};

//
// config_parser_t
//
/*!
 * @brief A class for parsing arataga's config.
 *
 * It's supposed that an instance of that class is created just
 * once and then reused.
 */
class config_parser_t
{
public:
	//! Type of exception for parsing errors.
	struct parser_exception_t : public exception_t
	{
	public:
		parser_exception_t( const std::string & what );
	};

	config_parser_t();
	~config_parser_t();

	//! Parse the content of the config.
	/*!
	 * @throw parser_exception_t in the case of an error.
	 */
	[[nodiscard]]
	config_t
	parse( std::string_view content );

private:
	struct impl_t;

	std::unique_ptr<impl_t> m_impl;
};

} /* namespace arataga */

