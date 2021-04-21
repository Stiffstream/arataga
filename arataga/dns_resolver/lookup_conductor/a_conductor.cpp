/*!
 * @file
 * @brief Implementation of dns_resolver-agent.
 */

#include <arataga/dns_resolver/lookup_conductor/a_conductor.hpp>
#include <arataga/dns_resolver/lookup_conductor/resolve_address_from_list.hpp>

#include <arataga/dns_resolver/interactor/pub.hpp>

#include <arataga/logging/wrap_logging.hpp>

#include <fmt/ostream.h>

namespace arataga::dns_resolver::lookup_conductor
{

namespace
{
	const std::chrono::seconds resolve_info_time_to_live{30};

	[[nodiscard]]
	std::string
	to_string( ip_version_t ver )
	{
		return ver == ip_version_t::ip_v4? "IPv4": "IPv6";
	}

	[[nodiscard]]
	inline std::string
	make_error_description( const asio::error_code & ec )
	{
		return fmt::format( "{}({})", ec.message(), ec.value() );
	}

} /* anonymous namespace */

//
// local_cache_t
//

std::optional<asio::ip::address>
local_cache_t::resolve(
	const std::string & name,
	ip_version_t ip_version ) const
{
	auto it = m_data.find(name);
	if( it != m_data.cend() )
	{
		const auto & addresses = it->second.m_addresses;

		return resolve_address_from_list(
			addresses,
			ip_version,
			[](const asio::ip::address & el)->
				const asio::ip::address &
			{
				return el;
			});
	}

	return std::nullopt;
}

std::size_t
local_cache_t::remove_outdated_records( const std::chrono::seconds & time_to_live )
{
	std::size_t n_removed{};

	for(auto it = m_data.begin(); it != m_data.end(); )
	{
		if( it->second.is_outdated(time_to_live) )
		{
			it = m_data.erase(it);
			++n_removed;
		}
		else
			++it;
	}

	return n_removed;
}

void
local_cache_t::add_records(
	std::string name,
	const interactor::successful_lookup_t::address_container_t & addresses )
{
	//FIXME: it seems that this method is not exception safe.
	//If assignement of m_addresses throws then an empty entry remains
	//in m_data.
	auto resolve_info = m_data.emplace(
		std::move(name),
		resolve_info_t{
			// The current timepoint is used as the creation time.
			std::chrono::steady_clock::now()
		} );

	resolve_info.first->second.m_addresses = addresses;
}

void
local_cache_t::clear()
{
	m_data.clear();
}

//
// a_dns_resolver
//
a_conductor_t::a_conductor_t(
	context_t ctx,
	application_context_t app_ctx,
	std::string name,
	ip_version_t ip_version,
	const so_5::mbox_t & incoming_requests_mbox,
	const so_5::mbox_t & nameserver_interactor_mbox )
	:	so_5::agent_t{ std::move(ctx) }
	,	m_app_ctx{ std::move(app_ctx) }
	,	m_name{ std::move(name) }
	,	m_ip_version{ ip_version }
	,	m_incoming_requests_mbox{ incoming_requests_mbox }
	,	m_nameserver_interactor_mbox{ nameserver_interactor_mbox }
	,	m_dns_stats_reg{
			m_app_ctx.m_dns_stats_manager,
			m_dns_stats
		}
	// NOTE: just a hardcoded value.
	// The actual value from config will be received after
	// the subscription to config_updates_mbox.
	,	m_cache_cleanup_period{ std::chrono::seconds{60} }
{}

void
a_conductor_t::so_define_agent()
{
	// We want to receive only requests for our IP-version.
	so_set_delivery_filter(
			m_incoming_requests_mbox,
			[ip_ver = m_ip_version]( const resolve_request_t & req ) {
				return ip_ver == req.m_ip_version;
			} );

	so_subscribe( m_incoming_requests_mbox )
		.event( &a_conductor_t::on_resolve );

	so_subscribe_self().event( &a_conductor_t::on_clear_cache );

	so_subscribe_self().event( &a_conductor_t::on_lookup_response );
}

void
a_conductor_t::so_evt_start()
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::info,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: started", m_name );
			} );

	// Subscription for config-updates should be made here because
	// config_updates_mbox is a retained mbox.
	so_subscribe( m_app_ctx.m_config_updates_mbox ).event(
		&a_conductor_t::on_updated_dns_params );

	so_5::send_delayed< clear_cache_t >( *this, m_cache_cleanup_period );
}

void
a_conductor_t::so_evt_finish()
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::info,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: shutdown completed", m_name );
			} );
}

void
a_conductor_t::on_resolve( const resolve_request_t & msg )
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::debug,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: resolve request: id={}, name={}, ip version={}",
						m_name,
						msg.m_req_id,
						msg.m_name,
						to_string( msg.m_ip_version ) );
			} );

	auto resolve = m_cache.resolve( msg.m_name, msg.m_ip_version );

	if( resolve )
	{
		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::debug,
				[&]( auto & logger, auto level )
				{
					logger.log(
							level,
							"{}: request resolved from cache: id={}, "
								"name={}, address={}",
							m_name,
							msg.m_req_id,
							msg.m_name,
							resolve->to_string() );
				} );

		// Update the stats.
		m_dns_stats.m_dns_cache_hits += 1u;

		forward::successful_resolve_t result{
			*resolve };

		so_5::send< resolve_reply_t >(
			msg.m_reply_to,
			msg.m_req_id,
			msg.m_completion_token,
			forward::resolve_result_t{ std::move(result) } );

		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::trace,
				[&]( auto & logger, auto level )
				{
					logger.log(
							level,
							"{}: resolve reply sent: id={}",
							m_name,
							msg.m_req_id);
				} );
	}
	else
	{
		add_to_waiting_and_resolve(msg);
	}
}

void
a_conductor_t::on_clear_cache( so_5::mhood_t<clear_cache_t> )
{
// This code fragment is kept here for the case when some debugging
// will be necessary.
#if 0
	std::ostringstream o;
	o << m_cache;
#endif

	const auto n_removed = m_cache.remove_outdated_records(
			resolve_info_time_to_live );

	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::debug,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: DNS cache cleaned up ({} item(s) removed)",
						m_name,
						n_removed );
			} );

	// Initiate the next cleanup.
	so_5::send_delayed< clear_cache_t >( *this, m_cache_cleanup_period );
}

void
a_conductor_t::on_updated_dns_params(
	const updated_dns_params_t & msg )
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::trace,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: update dns params", m_name );
			} );

	m_cache_cleanup_period = msg.m_cache_cleanup_period;
}

void
a_conductor_t::on_lookup_response(
	const interactor::lookup_response_t & msg )
{
	//FIXME: should a possible exception be handled?
	msg.m_result_processor( msg.m_result );
}

void
a_conductor_t::handle_lookup_result(
	std::string domain_name,
	interactor::lookup_result_t lookup_result )
{
	auto log_func =
		[this]( resolve_req_id_t req_id,
			const forward::resolve_result_t & result )
		{
			::arataga::logging::wrap_logging(
					direct_logging_mode,
					spdlog::level::trace,
					[&]( auto & logger, auto level )
					{
						logger.log(
								level,
								"{}: resolve reply sent: id={}, result={}",
								m_name,
								req_id,
								result );
					} );
		};

	const auto success_handler =
		[this, &domain_name, &log_func]
		( const interactor::successful_lookup_t & lr )
		{
			// The stats for successful DNS lookups has to be updated.
			m_dns_stats.m_dns_successful_lookups += 1u;

			//FIXME: should possible exceptions be ignored?
			::arataga::logging::wrap_logging(
					direct_logging_mode,
					spdlog::level::info,
					[&]( auto & logger, auto level )
					{
						std::string ips;
						for( const auto & addr: lr.m_addresses )
						{
							ips += addr.to_string();
							ips += ' ';
						}

						logger.log(
								level,
								"{}: async_resolve success: name={}, results=[{}]",
								m_name,
								domain_name,
								ips );
					} );

			m_cache.add_records( domain_name, lr.m_addresses );

			m_waiting_forward_requests.handle_waiting_requests(
				domain_name,
				lr.m_addresses,
				log_func,
				[]( const asio::ip::address & addr )
				{
					return addr;
				} );
		};

	const auto failure_handler =
		[this, &domain_name, &log_func]
		(const interactor::failed_lookup_t & lr )
		{
			// The stats for failed DNS lookups has to be updated.
			m_dns_stats.m_dns_failed_lookups += 1u;

			//FIXME: should possible exceptions be ignored?
			::arataga::logging::wrap_logging(
					direct_logging_mode,
					spdlog::level::warn,
					[&]( auto & logger, auto level )
					{
						logger.log(
								level,
								"{}: async_resolve failure: name={}, error={}",
								m_name,
								domain_name,
								lr.m_description );
					} );

			m_waiting_forward_requests.handle_waiting_requests(
				domain_name,
				forward::failed_resolve_t{ lr.m_description },
				log_func );
		};

	std::visit(
			::arataga::utils::overloaded{
					success_handler,
					failure_handler
			},
			lookup_result );
}

void
a_conductor_t::add_to_waiting_and_resolve(
	const resolve_request_t & req )
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::trace,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: request will be added to waiting list: id={}, name={}",
						m_name,
						req.m_req_id,
						req.m_name );
			} );

	bool need_resolve = m_waiting_forward_requests.add_request(
		req.m_name, req );

	if( need_resolve )
	{
		so_5::send< interactor::lookup_request_t >(
				m_nameserver_interactor_mbox,
				req.m_name,
				req.m_ip_version,
				so_direct_mbox(),
				// NOTE: there is no need to capture this via smart-pointer
				// because this handler will be returned via message.
				// That message will be ignored if the agent is already
				// deregistered.
				[this, name = req.m_name]
				( interactor::lookup_result_t lookup_result )
				{
					handle_lookup_result(
							std::move(name),
							std::move(lookup_result) );
				} );

		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::debug,
				[&]( auto & logger, auto level )
				{
					logger.log(
							level,
							"{}: async_resolve initiated: id={}, name={}",
							m_name,
							req.m_req_id,
							req.m_name );
				} );
	}
}

//
// add_lookup_conductors_to_coop
//
void
add_lookup_conductors_to_coop(
	so_5::coop_t & coop,
	application_context_t app_ctx,
	const std::string & name_prefix,
	const so_5::mbox_t & incoming_requests_mbox,
	const so_5::mbox_t & nameserver_interactor_mbox )
{
	// For IPv4.
	coop.make_agent< a_conductor_t >(
			app_ctx,
			name_prefix + ".ipv4",
			ip_version_t::ip_v4,
			incoming_requests_mbox,
			nameserver_interactor_mbox );
	// For IPv6.
	coop.make_agent< a_conductor_t >(
			app_ctx,
			name_prefix + ".ipv6",
			ip_version_t::ip_v6,
			incoming_requests_mbox,
			nameserver_interactor_mbox );
}

} /* namespace arataga::dns_resolver::lookup_conductor */
