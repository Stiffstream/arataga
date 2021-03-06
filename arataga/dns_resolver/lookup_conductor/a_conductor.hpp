/*!
 * @file
 * @brief The definition of dns_resolver_agent.
 */

#pragma once

#include <arataga/dns_resolver/pub.hpp>
#include <arataga/dns_resolver/interactor/pub.hpp>

#include <arataga/dns_resolver/lookup_conductor/waiting_requests_handler.hpp>

#include <arataga/config_processor/notifications.hpp>

#include <arataga/stats/dns/pub.hpp>

#include <asio/ip/tcp.hpp>

#include <map>
#include <chrono>
#include <list>

namespace arataga::dns_resolver::lookup_conductor
{

/*!
 * @brief Local cache for resolved domain names.
 *
 * Implemented as a map with the domain name as key. Address and resolution
 * time are stored as values.
 */
class local_cache_t
{
public:
	local_cache_t() = default;
	~local_cache_t() = default;

	/*!
	 * @brief Perform the resolution of a domain name.
	 *
	 * @return IP-address if name is present in the cache or empty value
	 * otherwise.
	 */
	[[nodiscard]]
	std::optional<asio::ip::address>
	resolve(
		//! Domain name to be resolved.
		const std::string & name ) const;

	/*!
	 * @brief Remove outdated items.
	 *
	 * @return Count of removed items.
	 */
	std::size_t
	remove_outdated_records(
		//! Max age for item in the cache.
		const std::chrono::seconds & time_to_live );

	/*!
	 * @brief Add an item to the cache.
	 */
	void
	add_records(
		//! Domain name to be added.
		std::string name,
		//! IP-addresses for that domain.
		const interactor::successful_lookup_t::address_container_t & addresses );

	/*!
	 * @brief Clear the cache.
	 */
	void
	clear();

	void dump( std::ostream & o ) const
	{
		o << "[";

		for( const auto & elem: m_data )
		{
			o << "{" << "{name " << elem.first << "}";
			o << "{age_sec " << elem.second.age().count() << "}";
			o << "[";

			for( const auto & addr: elem.second.m_addresses )
			{
				o << "{ip " << addr.to_string() << "}";
			}

			o << "]" << "}";
		}

		o << "]";
	}

private:

	/*!
	 * @brief The data for one resolved domain name.
	 */
	struct resolve_info_t
	{
		interactor::successful_lookup_t::address_container_t m_addresses;

		std::chrono::steady_clock::time_point m_creation_time;

		resolve_info_t(
			std::chrono::steady_clock::time_point creation_time,
			interactor::successful_lookup_t::address_container_t addresses )
			:	m_addresses{ std::move(addresses) }
			,	m_creation_time{ std::move(creation_time) }
		{
		}

		[[nodiscard]]
		std::chrono::seconds
		age() const
		{
			return
				std::chrono::duration_cast<std::chrono::seconds>(
					std::chrono::steady_clock::now() - m_creation_time );
		}

		/*!
		 * @brief Check the age of domain name info.
		 *
		 * @return true if domain name info is outdated.
		 */
		[[nodiscard]]
		bool
		is_outdated( const std::chrono::seconds & time_to_live ) const
		{
			return age() >= time_to_live;
		}
	};

	/*!
	 * @brief The map of resolved domain names.
	 *
	 * Domain name is used as the key.
	 */
	std::map< std::string, resolve_info_t > m_data;
};

inline std::ostream &
operator<<( std::ostream & o, const local_cache_t & cache )
{
	cache.dump(o);

	return o;
}

//
// direct_ip_checking_result_t
//
/*!
 * @since v.0.4.2
 */
enum class direct_ip_checking_result_t
{
	//! direct IP is specified instead of a domain name.
	direct_ip,
	//! a name is specified as domain name.
	domain_name
};

//
// a_conductor_t
//
/*!
 * @brief Agent for performing domain name resolution.
 */
class a_conductor_t final : public so_5::agent_t
{
public:
	//! Initializing constructor.
	a_conductor_t(
		//! SOEnv and SObjectizer-related parameters.
		context_t ctx,
		//! Aragata's context.
		application_context_t app_ctx,
		//! Unique name of that agent.
		std::string name,
		//! IP version to handle.
		ip_version_t ip_version,
		//! Mbox to be used for subscription to incoming requests.
		const so_5::mbox_t & incoming_requests_mbox,
		//! Mbox for outgoing requests to nameserver_interactor.
		const so_5::mbox_t & nameserver_interactor_mbox );

	void
	so_define_agent() override;

	void
	so_evt_start() override;

	void
	so_evt_finish() override;

private:
	//! The signal for cache cleanup.
	struct clear_cache_t final : public so_5::signal_t {};

	//! Arataga's context.
	const application_context_t m_app_ctx;

	//! Name of that agent.
	const std::string m_name;

	//! IP version to handle.
	const ip_version_t m_ip_version;

	//! Mbox to be used for subscription to incoming requests.
	const so_5::mbox_t m_incoming_requests_mbox;
	//! Mbox for outgoing requests to nameserver_interactor.
	const so_5::mbox_t m_nameserver_interactor_mbox;

	//! Agent's stats.
	::arataga::stats::dns::dns_stats_t m_dns_stats;
	::arataga::stats::dns::auto_reg_t m_dns_stats_reg;

	//! The current period for cache cleanup procedures.
	std::chrono::milliseconds m_cache_cleanup_period;

	//! The local cache for domain name.
	local_cache_t m_cache;

	//! List of waiting domain names.
	waiting_requests_handler_t m_waiting_forward_requests;

	//! Handler for a new resolution request.
	void
	on_resolve( const resolve_request_t & msg );

	//! Handler for cache cleanup event.
	void
	on_clear_cache( so_5::mhood_t<clear_cache_t> );

	using updated_dns_params_t =
		arataga::config_processor::updated_dns_params_t;

	//! Handler for configuration updates.
	void
	on_updated_dns_params(
		const updated_dns_params_t & msg );

	//! Handler for responses from nameserver_interactor.
	/*!
	 * @since v.0.4.0
	 */
	void
	on_lookup_response(
		const interactor::lookup_response_t & msg );

	//! The reaction to the result of DNS-lookup.
	void
	handle_lookup_result(
		//! Domain name to be resolved.
		std::string domain_name,
		//! The result of DNS-lookup.
		interactor::lookup_result_t lookup_result );

	/*!
	 * @brief Add a new request to the waiting list or initiate the resolution.
	 *
	 * Checks the presence of the domain name in waiting list. If it isn't
	 * in the list then initiate a new resolution.
	 */
	void
	add_to_waiting_and_resolve( const resolve_request_t & req );

	/*!
	 * @brief Handle a special case when direct IP address is
	 * specified instead of domain name.
	 *
	 * If a direct IP address is found then a response will be sent back.
	 *
	 * @since v.0.4.2
	 */
	[[nodiscard]]
	direct_ip_checking_result_t
	try_handle_direct_ip_case(
		const resolve_request_t & msg );
};

} /* namespace arataga::dns_resolver::lookup_conductor */

