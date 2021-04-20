/*!
 * @file
 * @brief Agent for interaction with nameservers.
 * @since v.0.4.0
 */

#pragma once

#include <arataga/dns_resolver/interactor/pub.hpp>

#include <arataga/dns_resolver/dns_types.hpp>

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
	//! Result processor for that request.
	result_processor_t m_result_processor;

	//! Buffer with outgoing data.
	std::array< char, max_dns_udp_package_size > m_outgoing_package;

	//! When processing of that request has been started.
	std::chrono::steady_clock::time_point m_start_time;

	//! Initializing constructor.
	ongoing_req_data_t(
		result_processor_t result_processor )
		:	m_result_processor{ std::move(result_processor) }
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

//FIXME: document this!
class a_nameserver_interactor_t final : public so_5::agent_t
{
public:
	a_nameserver_interactor_t(
		context_t ctx,
		params_t params );

	void
	so_define_agent() override;

	void
	so_evt_start() override;

private:
	//! Type of a container for holding ongoing requests.
	using ongoing_req_map_t = std::map<
			ongoing_req_id_t,
			ongoing_req_data_t >;

	//! Type of a container for holding info about name servers.
	using nameserver_info_container_t = std::vector< nameserver_info_t >;

	//! Personal parameters for that agent.
	const params_t m_params;

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

	void
	evt_lookup_request(
		mhood_t< lookup_request_t > cmd );

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
	form_and_send_dns_udp_package(
		const std::string_view domain_name,
		ip_version_t ip_version,
		// This is a reference to data stored inside m_ongoing_requests.
		const ongoing_req_id_t & req_id,
		// This is a reference to data stored inside m_ongoing_requests.
		ongoing_req_data_t & req_data );

	void
	handle_async_send_result(
		ongoing_req_id_t req_id,
		const asio::error_code & ec,
		std::size_t bytes_transferred ) noexcept;
};

} /* namespace arataga::dns_resolver::interactor */

