/*!
 * @file
 * @brief The definition of dns_resolver_agent.
 */

#pragma once

#include <arataga/dns_resolver/pub.hpp>
#include <arataga/dns_resolver/waiting_requests_handler.hpp>
#include <arataga/config_processor/notifications.hpp>

#include <arataga/stats/dns/pub.hpp>

#include <asio/ip/tcp.hpp>

#include <map>
#include <chrono>
#include <list>

namespace arataga::dns_resolver
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
		const std::string & name,
		//! IPv4 or IPv6 address as result?
		ip_version_t ip_version ) const;

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
		const asio::ip::tcp::resolver::results_type & results );

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
		std::list< asio::ip::address > m_addresses;

		std::chrono::steady_clock::time_point m_creation_time;

		resolve_info_t(
			std::chrono::steady_clock::time_point creation_time )
			:	m_creation_time{ std::move(creation_time) }
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
// a_dns_resolver_t
//
/*!
 * @brief Agent for performing domain name resolution.
 */
class a_dns_resolver_t final : public so_5::agent_t
{
public:
	//! Initializing constructor.
	a_dns_resolver_t(
		//! SOEnv and SObjectizer-related parameters.
		context_t ctx,
		//! Aragata's context.
		application_context_t app_ctx,
		//! Initial parameters for that agent.
		params_t params );

	void
	so_define_agent() override;

	void
	so_evt_start() override;

	void
	so_evt_finish() override;

private:

	//! The signal for cache cleanup.
	struct clear_cache_t final : public so_5::signal_t {};

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

	//! The reaction to the resolution result.
	void
	handle_resolve_result(
		//! Low-level error from Asio.
		const asio::error_code & ec,
		//! IP-addresses for the domain name.
		asio::ip::tcp::resolver::results_type results,
		//! Domain name.
		std::string name );

	//! Arataga's context.
	const application_context_t m_app_ctx;

	//! Initial parameters for that agent.
	const params_t m_params;

	//! Agent's stats.
	::arataga::stats::dns::dns_stats_t m_dns_stats;
	::arataga::stats::dns::auto_reg_t m_dns_stats_reg;

	//! The current period for cache cleanup procedures.
	std::chrono::milliseconds m_cache_cleanup_period;

	//! Экземпляр resolver-а из asio.
	asio::ip::tcp::resolver m_resolver;

	//! The local cache for domain name.
	local_cache_t m_cache;

	/*!
	 * @brief Add a new request to the waiting list or initiate the resolution.
	 *
	 * Checks the presence of the domain name in waiting list. If it isn't
	 * in the list then initiate a new resolution.
	 */
	void
	add_to_waiting_and_resolve( const resolve_request_t & req );

	waiting_requests_handler_t<
		std::string,
		resolve_request_t,
		resolve_reply_t > m_waiting_forward_requests;
};

} /* namespace arataga::dns_resolver */

