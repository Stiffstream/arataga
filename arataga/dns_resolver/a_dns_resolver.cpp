/*!
 * @file
 * @brief Implementation of dns_resolver-agent.
 */

#include <arataga/dns_resolver/a_dns_resolver.hpp>
#include <arataga/dns_resolver/resolve_address_from_list.hpp>

#include <arataga/logging/wrap_logging.hpp>

#include <fmt/ostream.h>

namespace arataga::dns_resolver
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
	const asio::ip::tcp::resolver::results_type & results )
{
	auto resolve_info = m_data.emplace(
		std::move(name),
		resolve_info_t(
			// The current timepoint is used as the creation time.
			std::chrono::steady_clock::now() ) );

	for( const auto & ep: results )
	{
		resolve_info.first->second.m_addresses.push_back(
			ep.endpoint().address() );
	}
}

void
local_cache_t::clear()
{
	m_data.clear();
}

//
// a_dns_resolver
//
a_dns_resolver_t::a_dns_resolver_t(
	context_t ctx,
	application_context_t app_ctx,
	params_t params )
	:	so_5::agent_t{ std::move(ctx) }
	,	m_app_ctx{ std::move(app_ctx) }
	,	m_params{ std::move(params) }
	,	m_dns_stats_reg{
			m_app_ctx.m_dns_stats_manager,
			m_dns_stats
		}
	,	m_cache_cleanup_period{ m_params.m_cache_cleanup_period }
	,	m_resolver{ m_params.m_io_ctx }
{}

void
a_dns_resolver_t::so_define_agent()
{
	so_subscribe_self().event( &a_dns_resolver_t::on_resolve );

	so_subscribe_self().event( &a_dns_resolver_t::on_clear_cache );

	so_subscribe( m_app_ctx.m_config_updates_mbox ).event(
		&a_dns_resolver_t::on_updated_dns_params );
}

void
a_dns_resolver_t::so_evt_start()
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::info,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: started", m_params.m_name );
			} );

	so_5::send_delayed< clear_cache_t >( *this, m_cache_cleanup_period );
}

void
a_dns_resolver_t::so_evt_finish()
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::info,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: shutdown completed", m_params.m_name );
			} );
}

void
a_dns_resolver_t::on_resolve( const resolve_request_t & msg )
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::debug,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: resolve request: id={}, name={}, ip version={}",
						m_params.m_name,
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
							m_params.m_name,
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
							m_params.m_name,
							msg.m_req_id);
				} );
	}
	else
	{
		add_to_waiting_and_resolve(msg);
	}
}

void
a_dns_resolver_t::on_clear_cache( so_5::mhood_t<clear_cache_t> )
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
						m_params.m_name,
						n_removed );
			} );

	// Initiate the next cleanup.
	so_5::send_delayed< clear_cache_t >( *this, m_cache_cleanup_period );
}

void
a_dns_resolver_t::on_updated_dns_params(
	const updated_dns_params_t & msg )
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::trace,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: update dns params", m_params.m_name );
			} );

	m_cache_cleanup_period = msg.m_cache_cleanup_period;
}

void
a_dns_resolver_t::handle_resolve_result(
	const asio::error_code & ec,
	asio::ip::tcp::resolver::results_type results,
	std::string name )
{
	auto log_func =
		[this]( resolve_req_id_t req_id,
				forward::resolve_result_t result )
	{
		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::trace,
				[&]( auto & logger, auto level )
				{
					logger.log(
							level,
							"{}: resolve reply sent: id={}, result={}",
							m_params.m_name,
							req_id,
							result );
				} );
	};

	if( !ec )
	{
		// The stats for successful DNS lookups has to be updated.
		m_dns_stats.m_dns_successful_lookups += 1u;

		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::info,
				[&]( auto & logger, auto level )
				{
					std::string ips;
					for( const auto & ep: results )
					{
						ips += ep.endpoint().address().to_string();
						ips += ' ';
					}

					logger.log(
							level,
							"{}: domain resolved: name={}, results=[{}]",
							m_params.m_name,
							name,
							ips );
				} );

		m_cache.add_records( name, results );

		using resolver_value_type =
			asio::ip::tcp::resolver::results_type::value_type;

		m_waiting_forward_requests.handle_waiting_requests(
			name,
			results,
			log_func,
			[]( const resolver_value_type & el )
			{
				return el.endpoint().address();
			} );
	}
	else
	{
		// The stats for failed DNS lookups has to be updated.
		m_dns_stats.m_dns_failed_lookups += 1u;

		const auto error_desc = make_error_description(ec);
		forward::resolve_result_t result = forward::failed_resolve_t{
				 error_desc
			};

		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::warn,
				[&]( auto & logger, auto level )
				{
					logger.log(
							level,
							"{}: domain resolution failure: name={}, error={}",
							m_params.m_name,
							name,
							error_desc );
				} );

		m_waiting_forward_requests.handle_waiting_requests(
			name, std::move(result), log_func );
	}
}

void
a_dns_resolver_t::add_to_waiting_and_resolve(
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
						m_params.m_name,
						req.m_req_id,
						req.m_name );
			} );

	bool need_resolve = m_waiting_forward_requests.add_request(
		req.m_name, req );

	if( need_resolve )
	{
		// Service name should be treated as a numeric string
		//defining a port number and no name resolution should be attempted.
		auto resolve_flags = asio::ip::tcp::resolver::numeric_service;
		// If used with v4_mapped, return all matching IPv6 and IPv4 addresses.
		resolve_flags |= asio::ip::tcp::resolver::all_matching;
		// If the query protocol family is specified as IPv6, return IPv4-mapped
		// IPv6 addresses on finding no IPv6 addresses.
		resolve_flags |= asio::ip::tcp::resolver::v4_mapped;

		m_resolver.async_resolve(
			req.m_name,
			std::string(),
			resolve_flags,
			[self = so_5::make_agent_ref(this), name = req.m_name]
			( const asio::error_code & ec,
				asio::ip::tcp::resolver::results_type results )
			{
				self->handle_resolve_result(
					ec, results,
					std::move(name) );
			} );

		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::debug,
				[&]( auto & logger, auto level )
				{
					logger.log(
							level,
							"{}: async_resolve initiated: id={}, name={}",
							m_params.m_name,
							req.m_req_id,
							req.m_name );
				} );
	}
}

//
// introduce_dns_resolver
//

std::tuple< so_5::coop_handle_t, so_5::mbox_t >
introduce_dns_resolver(
	so_5::environment_t & env,
	so_5::coop_handle_t parent_coop,
	so_5::disp_binder_shptr_t disp_binder,
	application_context_t app_ctx,
	params_t params )
{
	auto coop_holder = env.make_coop( parent_coop, std::move(disp_binder) );
	auto dns_mbox = coop_holder->make_agent< a_dns_resolver_t >(
			std::move(app_ctx),
			std::move(params) )->so_direct_mbox();

	auto h_coop = env.register_coop( std::move(coop_holder) );

	return { std::move(h_coop), std::move(dns_mbox) };
}

} /* namespace arataga::dns_resolver */

