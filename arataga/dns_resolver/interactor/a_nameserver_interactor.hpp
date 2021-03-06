/*!
 * @file
 * @brief Agent for interaction with nameservers.
 * @since v.0.4.0
 */

#pragma once

#include <arataga/dns_resolver/interactor/pub.hpp>

#include <arataga/dns_resolver/dns_types.hpp>

#include <arataga/config_processor/notifications.hpp>

#include <arataga/one_second_timer.hpp>

#include <oess_2/io/h/stream.hpp>

#include <asio/ip/udp.hpp>

namespace arataga::dns_resolver::interactor
{

//
// lookup_req_id_t
//
using lookup_req_id_t = oess_2::ushort_t;

//
// max_dns_udp_package_size
//
// See https://tools.ietf.org/html/rfc1035 section 4.2.1.
inline constexpr std::size_t max_dns_udp_package_size = 512u;

//
// ongoing_req_data_t
//
struct ongoing_req_data_t
{
	//! Name to be resolved.
	/*!
	 * It's needed for logging in the case of some strange responses
	 * from DNS server.
	 */
	std::string m_domain_name;

	//! Mbox for the result.
	so_5::mbox_t m_reply_to;

	//! Result processor for that request.
	result_processor_t m_result_processor;

	//! Buffer with outgoing data.
	std::array< char, max_dns_udp_package_size > m_outgoing_package;

	//! When processing of that request has been started.
	std::chrono::steady_clock::time_point m_start_time;

	//! Initializing constructor.
	ongoing_req_data_t(
		std::string domain_name,
		so_5::mbox_t reply_to,
		result_processor_t result_processor )
		:	m_domain_name{ std::move(domain_name) }
		,	m_reply_to{ std::move(reply_to) }
		,	m_result_processor{ std::move(result_processor) }
		,	m_start_time{ std::chrono::steady_clock::now() }
	{}
};

//
// ongoing_req_id_t
//
struct ongoing_req_id_t
{
	//! ID from DNS package.
	lookup_req_id_t m_id;
	//! IP-address of nameserver.
	asio::ip::address m_address;

	[[nodiscard]]
	auto
	tie() const noexcept
	{
		return std::tie(m_id, m_address);
	}
};

[[nodiscard]]
inline bool
operator==(
	const ongoing_req_id_t & a,
	const ongoing_req_id_t & b ) noexcept
{
	return a.tie() == b.tie();
}

[[nodiscard]]
inline bool
operator!=(
	const ongoing_req_id_t & a,
	const ongoing_req_id_t & b ) noexcept
{
	return a.tie() != b.tie();
}

[[nodiscard]]
inline bool
operator<(
	const ongoing_req_id_t & a,
	const ongoing_req_id_t & b ) noexcept
{
	return a.tie() < b.tie();
}

inline std::ostream &
operator<<(
	std::ostream & to, const ongoing_req_id_t & id )
{
	return (to << '(' << id.m_address << '#' << id.m_id << ')');
}

//
// nameserver_info_t
//
struct nameserver_info_t
{
	//! IP-address of name server.
	asio::ip::address m_address;

	//! Counter for requests ID for that server.
	lookup_req_id_t m_req_id_counter{};

	//! Initializing constructor.
	nameserver_info_t(
		asio::ip::address address )
		:	m_address{ std::move(address) }
	{}
};

//
// a_nameserver_interactor_t
//

/*!
 * @brief Agent that performs interaction with DNS servers via UDP.
 *
 * Handles incoming lookup_request_t and translates them into
 * outgoing UDP packages to a DNS server. Controls the lifetime of
 * every request sent to a DNS server.
 *
 * Handles the config updates from config_processor.
 */
class a_nameserver_interactor_t final : public so_5::agent_t
{
public:
	a_nameserver_interactor_t(
		context_t ctx,
		application_context_t app_ctx,
		params_t params );

	void
	so_define_agent() override;

	void
	so_evt_start() override;

	void
	so_evt_finish() override;

private:
	//! Type of a container for holding ongoing requests.
	using ongoing_req_map_t = std::map<
			ongoing_req_id_t,
			ongoing_req_data_t >;

	//! Type of a container for holding info about name servers.
	using nameserver_info_container_t = std::vector< nameserver_info_t >;

	//! Arataga's context.
	const application_context_t m_app_ctx;

	//! Personal parameters for that agent.
	const params_t m_params;

	//! Time for waiting the reply from name server.
	std::chrono::milliseconds m_dns_resolving_timeout;

	//! UPD socket to be user for interaction with nameservers.
	asio::ip::udp::socket m_socket;

	//! Receiver of endpoint of last incoming package.
	asio::ip::udp::endpoint m_incoming_pkg_endpoint;

	//! Buffer for incoming packages.
	std::array< char, max_dns_udp_package_size > m_incoming_pkg;

	//! Name servers to be used.
	nameserver_info_container_t m_nservers;
	//! Index of last used name server.
	/*!
	 * @note
	 * Should be dropped to 0 after the update of m_nservers content.
	 */
	std::size_t m_last_nserver_index{};

	//! Ongoing requests.
	ongoing_req_map_t m_ongoing_requests;

	//! Is the agent finished its work?
	/*!
	 * Set to `true` in so_evt_finish.
	 *
	 * While it is not `true` the next async_receive_from has to be called
	 * even if the previous call completed with an error.
	 */
	bool m_is_finished = false;

	//! Handler for a new lookup_request.
	void
	evt_lookup_request(
		mhood_t< lookup_request_t > cmd );

	//! Handler for configuration updates.
	void
	evt_updated_dns_params(
		mhood_t< arataga::config_processor::updated_dns_params_t > msg );

	//! Handler for timer events.
	/*!
	 * Checks lifetimes of ongoing requests.
	 */
	void
	evt_one_second_timer(
		mhood_t< arataga::one_second_timer_t > );

	// Returns nullptr if there is no name servers to be used.
	[[nodiscard]]
	nameserver_info_t *
	detect_nsrv_for_new_request() noexcept;

	void
	initiate_next_async_read();

	void
	handle_async_receive_result(
		const asio::error_code & ec,
		std::size_t bytes_transferred ) noexcept;

	void
	try_handle_incoming_pkg(
		std::size_t bytes_transferred );

	void
	try_handle_positive_nameserver_response(
		std::string_view all_bin_data,
		oess_2::io::istream_t & bin_stream,
		dns_header_t header );

	void
	try_handle_negative_nameserver_response(
		dns_header_t header );

	// NOTE: handles (ignores) all exceptions.
	void
	form_and_send_dns_udp_package(
		const std::string_view & domain_name,
		ip_version_t ip_version,
		// This is a reference to data stored inside m_ongoing_requests.
		const ongoing_req_id_t & req_id,
		// This is a reference to data stored inside m_ongoing_requests.
		ongoing_req_data_t & req_data ) noexcept;

	// NOTE: suppresses all exceptions.
	void
	handle_dns_udp_package_sending_failure(
		const ongoing_req_id_t & req_id,
		ongoing_req_data_t & req_data,
		const char * failure_description ) noexcept;

	void
	handle_async_send_result(
		ongoing_req_id_t req_id,
		const asio::error_code & ec,
		std::size_t bytes_transferred ) noexcept;

	void
	update_nameservers_list(
		config_t::nameserver_ip_container_t nameserver_ips );
};

} /* namespace arataga::dns_resolver::interactor */

