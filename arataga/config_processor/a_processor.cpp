/*!
 * @file
 * @brief Agent for handling arataga's configuration.
 */

#include <arataga/config_processor/a_processor.hpp>

#include <arataga/config_processor/notifications.hpp>

#include <arataga/authentificator/pub.hpp>
#include <arataga/dns_resolver/pub.hpp>

#include <arataga/acl_handler/pub.hpp>

#include <arataga/admin_http_entry/helpers.hpp>

#include <arataga/utils/load_file_into_memory.hpp>
#include <arataga/utils/opt_username_dumper.hpp>

#include <arataga/logging/wrap_logging.hpp>

#include <arataga/exception.hpp>

#include <fmt/ostream.h>
#include <fmt/format.h>

#include <algorithm>
#include <fstream>
#include <iterator>
#include <random>
#include <limits>

namespace arataga::config_processor
{

//
// config_processor_ex_t
//
//! Type for an exception for config_processor agent.
struct config_processor_ex_t : public exception_t
{
public:
	config_processor_ex_t( const std::string & what )
		:	exception_t{ what }
	{}
};

namespace
{

[[nodiscard]]
auto
make_port_and_in_addr_tuple( const acl_config_t & v ) noexcept
{
	return std::tie( v.m_port, v.m_in_addr );
}

[[nodiscard]]
bool
port_and_in_addr_less_comparator(
	const acl_config_t & a, const acl_config_t & b ) noexcept
{
	return make_port_and_in_addr_tuple(a) < make_port_and_in_addr_tuple(b);
}

[[nodiscard]]
bool
port_and_in_addr_equal_comparator(
	const acl_config_t & a, const acl_config_t & b ) noexcept
{
	return make_port_and_in_addr_tuple(a) == make_port_and_in_addr_tuple(b);
}

[[nodiscard]]
auto
make_full_acl_identity_tuple( const acl_config_t & v ) noexcept
{
	return std::tie( v.m_port, v.m_in_addr, v.m_out_addr, v.m_protocol );
}

// Throws an exception if there is a pair of ACL with the same (port, in_ip).
void
sort_acl_list_and_ensure_uniqueness(
	config_t::acl_container_t & acls )
{
	std::sort( acls.begin(), acls.end(), port_and_in_addr_less_comparator );
	const auto same_it = std::adjacent_find( acls.begin(), acls.end(),
			port_and_in_addr_equal_comparator );
	if( same_it != acls.end() )
		throw config_processor_ex_t{
				fmt::format(
						"config_processor: not unique (port, in_ip) pair "
						"found: ({}, {})",
						same_it->m_port,
						same_it->m_in_addr )
			};
}

// A tricky comparator for comparing running_acl_info_t with acl_config_t.
struct tricky_acl_comparator_t
{
	[[nodiscard]] bool
	operator()(
		const acl_config_t & a,
		const a_processor_t::running_acl_info_t & b )
	{
		return make_full_acl_identity_tuple( a ) <
			make_full_acl_identity_tuple( b.m_config );
	}

	[[nodiscard]] bool
	operator()(
		const a_processor_t::running_acl_info_t & a,
		const acl_config_t & b )
	{
		return make_full_acl_identity_tuple( a.m_config ) <
				make_full_acl_identity_tuple( b );
	}
};

// Helper for generation the first ACL ID seed.
[[nodiscard]]
arataga::utils::acl_req_id_seed_t
make_initial_acl_req_id_seed()
{
	using seed_t = arataga::utils::acl_req_id_seed_t::seed_t;
	std::mt19937 generator{ std::random_device{}() };
	std::uniform_int_distribution< seed_t > distribution{
			0u,
			// It seems that at most 4 decimal digits are enough.
			9999u
	};

	return { distribution( generator ), 0u };
}

// NOTE: modifies its parameter!
[[nodiscard]]
arataga::utils::acl_req_id_seed_t
make_next_acl_req_id_seed(
	arataga::utils::acl_req_id_seed_t & last_value )
{
	last_value.m_ordinal += 1u;
	return last_value;
}

} /* namespace anonymous */

//
// a_processor_t
//
a_processor_t::a_processor_t(
	context_t ctx,
	application_context_t app_ctx,
	params_t params )
	:	so_5::agent_t{ std::move(ctx) }
	,	m_app_ctx{ std::move(app_ctx) }
	,	m_params{ std::move(params) }
	,	m_local_config_file_name{
			m_params.m_local_config_path / "local-config.cfg" }
	,	m_acl_id_seed{ make_initial_acl_req_id_seed() }
	,	m_own_acl_id_seed{ make_next_acl_req_id_seed( m_acl_id_seed ) }
{
}

void
a_processor_t::so_define_agent()
{
	so_subscribe( m_app_ctx.m_config_processor_mbox )
		.event( &a_processor_t::on_new_config )
		.event( &a_processor_t::on_get_acl_list )
		.event( &a_processor_t::on_debug_auth )
		.event( &a_processor_t::on_debug_dns_resolve );

	// Replies for test authentification and doman name resolution
	// will go to the direct mbox.
	so_subscribe_self()
		.event( &a_processor_t::on_auth_reply )
		.event( &a_processor_t::on_resolve_reply );
}

void
a_processor_t::so_evt_start()
{
	try_load_local_config_first_time();

	// Notify about successful start.
	so_5::send< started_t >( m_params.m_startup_notify_mbox );
}

void
a_processor_t::on_new_config(
	mhood_t< new_config_t > cmd )
{
	namespace http_entry = ::arataga::admin_http_entry;

	http_entry::envelope_sync_request_handling(
			"config_processor::a_processor_t::on_new_config",
			*(cmd->m_replier),
			http_entry::status_config_processor_failure,
			[&]() -> http_entry::replier_t::reply_params_t
			{
				try_handle_new_config_from_post_request( cmd->m_content );

				// If we are here then everything is OK.
				return http_entry::replier_t::reply_params_t{
						http_entry::status_ok,
						"New config accepted\r\n"
				};
			} );
}

void
a_processor_t::on_get_acl_list(
	mhood_t< get_acl_list_t > cmd )
{
	namespace http_entry = ::arataga::admin_http_entry;

	http_entry::envelope_sync_request_handling(
			"config_processor::a_processor_t::on_get_acl_list",
			*(cmd->m_replier),
			http_entry::status_config_processor_failure,
			[&]() -> http_entry::replier_t::reply_params_t
			{
				std::string reply;

				for( const auto & racl : m_running_acls )
				{
					fmt::format_to(
							std::back_inserter(reply),
							"thread #{:>3}, ACL: {}\r\n",
							racl.m_io_thread_index,
							racl.m_config );
				}

				// If we are here then everything is OK.
				return http_entry::replier_t::reply_params_t{
						http_entry::status_ok,
						std::move(reply)
				};
			} );
}

void
a_processor_t::on_debug_auth(
	mhood_t< debug_auth_t > cmd )
{
	namespace http_entry = ::arataga::admin_http_entry;

	using ::arataga::opt_username_dumper::opt_username_dumper_t;
	using ::arataga::opt_username_dumper::opt_password_dumper_t;

	http_entry::envelope_async_request_handling(
			"config_processor::a_processor_t::on_debug_auth",
			*(cmd->m_replier),
			http_entry::status_config_processor_failure,
			[&]() {
				::arataga::logging::wrap_logging(
						direct_logging_mode,
						spdlog::level::debug,
						[&]( auto & logger, auto level )
						{
							logger.log(
									level,
									"config_processor: debug_auth received, "
									"proxy_in_addr={}, proxy_port={}, user_ip={}"
									"username={} (password={}), target_host={}, "
									"target_port={}",
									cmd->m_request.m_proxy_in_addr,
									cmd->m_request.m_proxy_port,
									cmd->m_request.m_user_ip,
									opt_username_dumper_t{cmd->m_request.m_username},
									opt_password_dumper_t{cmd->m_request.m_password},
									cmd->m_request.m_target_host,
									cmd->m_request.m_target_port );
						} );

				initiate_debug_auth_processing(
						cmd->m_replier,
						cmd->m_request );
			} );
}

void
a_processor_t::on_auth_reply(
	mhood_t< ::arataga::authentificator::auth_reply_t > cmd )
{
	if( cmd->m_completion_token )
		cmd->m_completion_token->complete( cmd->m_result );
}

void
a_processor_t::on_debug_dns_resolve(
	mhood_t< debug_dns_resolve_t > cmd )
{
	namespace http_entry = ::arataga::admin_http_entry;

	http_entry::envelope_async_request_handling(
			"config_processor::a_processor_t::on_debug_dns_resolve",
			*(cmd->m_replier),
			http_entry::status_config_processor_failure,
			[&]() {
				::arataga::logging::wrap_logging(
						direct_logging_mode,
						spdlog::level::debug,
						[&]( auto & logger, auto level )
						{
							logger.log(
									level,
									"config_processor: debug_dns_resolve received, "
									"proxy_in_addr={}, proxy_port={}, target_host={}",
									cmd->m_request.m_proxy_in_addr,
									cmd->m_request.m_proxy_port,
									cmd->m_request.m_target_host );
						} );

				initiate_debug_dns_resolve_processing(
						cmd->m_replier,
						cmd->m_request );
			} );
}

void
a_processor_t::on_resolve_reply(
	mhood_t< ::arataga::dns_resolver::resolve_reply_t > cmd )
{
	if( cmd->m_completion_token )
		cmd->m_completion_token->complete( cmd->m_result );
}

void
a_processor_t::try_load_local_config_first_time()
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::info,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"config_processor: trying load local "
						"config file at startup, local_config_file_name: {}",
						m_local_config_file_name );
			} );

	// Exceptions thrown during config loading will be ignored because
	// even in the case of a failure we will receive the new config
	// from HTTP-entry sooner or later.
	try
	{
		// Use lambda to destroy `content` as soon as possible.
		// It's because the content of `content` isn't needed anymore.
		auto config = [this] {
			// Load the content into the RAM...
			auto content = ::arataga::utils::load_file_into_memory(
					m_local_config_file_name );
			::arataga::logging::wrap_logging(
					direct_logging_mode,
					spdlog::level::trace,
					[&content]( auto & logger, auto level )
					{
						logger.log(
								level,
								"config_processor: {} byte(s) loaded "
								"from local config file",
								content.size() );
					} );

			// ...then try to parse it.
			return m_parser.parse( std::string_view{
					content.data(), content.size() } );
		}();

		try_handle_just_parsed_config( std::move(config) );
	}
	catch( const std::exception & x )
	{
		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::info,
				[&x]( auto & logger, auto level )
				{
					logger.log(
							level,
							"config_processor: load local "
							"config file at startup failed: {}",
							x.what() );
				} );
	}
}

void
a_processor_t::try_handle_new_config_from_post_request(
	std::string_view content )
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::info,
			[&content]( auto & logger, auto level )
			{
				logger.log(
						level,
						"config_processor: {} byte(s) received "
						"from admin HTTP-entry",
						content.size() );
			} );

	// Try to parse the config...
	auto config = m_parser.parse( content );

	// ...then process it.
	try_handle_just_parsed_config( std::move(config) );

	store_new_config_to_file( content );

	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::info,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"config_processor: new config processed" );
			} );
}

void
a_processor_t::try_handle_just_parsed_config(
	config_t config )
{
	// New acl-list should be sorted and should not contain duplicates.
	sort_acl_list_and_ensure_uniqueness( config.m_acls );

	// New the new config has to be applied to the whole app.
	accept_new_config( std::move(config) );
}

void
a_processor_t::accept_new_config( config_t config ) noexcept
{
	bool needs_terminate = false;

	// Version number can be incremented because config is valid at this point.
	m_config_update_counter += 1u;

	try
	{
		// Logging parameters may have been changed.
		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::trace,
				[&]( auto & logger, auto level )
				{
					logger.log(
							level,
							"config_processor: applying log_level from config: {}",
							spdlog::level::to_string_view( config.m_log_level ) );
				} );
		::arataga::logging::impl::logger().set_level( config.m_log_level );

		// Spread the new info from config.
		// The new config info will be accepted by authentificators and
		// dns_resolvers.
		send_updated_config_messages( config );

		// If the ACL list have been changed we should handle it.
		handle_upcoming_acl_list( config );
	}
	catch( const std::exception & x )
	{
		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::critical,
				[&x]( auto & logger, auto level )
				{
					logger.log(
							level,
							"config_processor: "
							"an exception caught during accepting new config: {}",
							x.what() );
				} );

		needs_terminate = true;
	}
	catch( ... )
	{
		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::critical,
				[]( auto & logger, auto level )
				{
					logger.log(
							level,
							"config_processor: "
							"unknown exception caught during accepting new config" );
				} );

		needs_terminate = true;
	}

	if( needs_terminate )
	{
		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::critical,
				[]( auto & logger, auto level )
				{
					logger.log(
							level,
							"config_processor: "
							"work can't be continued, aborting..." );
				} );

		std::abort();
	}
}

void
a_processor_t::send_updated_config_messages(
	const config_t & config )
{
	so_5::send< updated_dns_params_t >(
			m_app_ctx.m_config_updates_mbox,
			config.m_dns_cache_cleanup_period,
			config.m_common_acl_params.m_dns_resolving_timeout );

	so_5::send< updated_common_acl_params_t >(
			m_app_ctx.m_config_updates_mbox,
			config.m_common_acl_params );

	so_5::send< updated_auth_params_t >(
			m_app_ctx.m_config_updates_mbox,
			config.m_denied_ports,
			config.m_common_acl_params.m_failed_auth_reply_timeout );
}

void
a_processor_t::handle_upcoming_acl_list(
	const config_t & config )
{
	// New io_threads should be launched.
	create_dispatchers_if_necessary( config );

	// If there are some outdated ACLs they should be removed.
	stop_and_remove_outdated_acls( config );

	// If there are new ACLs they should be started.
	launch_new_acls( config );
}

namespace
{

[[nodiscard]]
std::size_t
detect_io_threads_count(
	const io_threads_count_t & count ) noexcept
{
	return std::visit(
			[]( const auto & v ) noexcept -> std::size_t { return v.detect(); },
			count );
}

} /* namespace anonymous */

void
a_processor_t::create_dispatchers_if_necessary(
	const config_t & config )
{
	if( !m_io_threads.empty() )
		return;

	const std::size_t threads_count = detect_io_threads_count(
			m_params.m_io_threads_count );

	m_io_threads.reserve( threads_count );

	for( std::size_t i = 0; i != threads_count; ++i )
	{
		io_thread_info_t info;

		info.m_disp = so_5::extra::disp::asio_one_thread::make_dispatcher(
				so_environment(),
				fmt::format( "io_thr_{}", i ),
				so_5::extra::disp::asio_one_thread::disp_params_t{}
						.use_own_io_context()
			);

		// New authentificator agent should be created for the IO-thread.
		std::tie( info.m_auth_coop, info.m_auth_mbox ) =
				::arataga::authentificator::
						introduce_authentificator(
								so_environment(),
								so_coop(), // We as the parent coop.
								info.m_disp.binder(),
								m_app_ctx,
								::arataga::authentificator::params_t{
										fmt::format( "io_thr_{}_auth", i )
								}
							);

		// New dns_resolver agent should be created for the IO-thread.
		std::tie( info.m_dns_coop, info.m_dns_mbox ) =
				::arataga::dns_resolver::
						introduce_dns_resolver(
								so_environment(),
								so_coop(), // We as the parent coop.
								info.m_disp.binder(),
								m_app_ctx,
								::arataga::dns_resolver::params_t{
										info.m_disp.io_context(),
										info.m_disp.binder(),
										fmt::format( "io_thr_{}_dns", i ),
										config.m_dns_cache_cleanup_period
								}
							);

		m_io_threads.emplace_back( std::move(info) );
	}

	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::trace,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"config_processor: {} IO-thread(s) started",
						threads_count );
			} );
}

void
a_processor_t::stop_and_remove_outdated_acls(
	const config_t & config )
{
	// Form a list of outdated ACLs.
	running_acl_container_t outdated_acls;
	std::set_difference(
			m_running_acls.begin(), m_running_acls.end(),
			config.m_acls.begin(), config.m_acls.end(),
			std::back_inserter( outdated_acls ),
			tricky_acl_comparator_t{} );

	{
		// Form a list of live ACLs.
		// Use a nested scope to limit the lifetime of living_acls.
		running_acl_container_t living_acls;
		std::set_intersection(
				m_running_acls.begin(), m_running_acls.end(),
				config.m_acls.begin(), config.m_acls.end(),
				std::back_inserter( living_acls ),
				tricky_acl_comparator_t{} );

		// The list of live ACLs will become the current ACL list.
		swap( m_running_acls, living_acls );
	}

	// Handle outdated ACL.
	for( auto & racl : outdated_acls )
	{
		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::debug,
				[&racl]( auto & logger, auto level )
				{
					logger.log(
							level,
							"config_processor: removing outdated ACL: {}",
							racl.m_config );
				} );

		so_5::send< ::arataga::acl_handler::shutdown_t >( racl.m_mbox );

		m_io_threads[ racl.m_io_thread_index ].m_running_acl_count -= 1u;
	}
}

void
a_processor_t::launch_new_acls(
	const config_t & config )
{
	// Form a list of new ACLs from the config.
	config_t::acl_container_t new_acl;
	std::set_difference(
			config.m_acls.begin(), config.m_acls.end(),
			m_running_acls.begin(), m_running_acls.end(),
			std::back_inserter( new_acl ),
			tricky_acl_comparator_t{} );

	// Start to bind new ACLs from the IO-thread with the lowest ACL count.
	auto io_thread_index = index_of_io_thread_with_lowest_acl_count();

	for( const auto & acl_conf : new_acl )
	{
		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::debug,
				[&acl_conf]( auto & logger, auto level )
				{
					logger.log(
							level,
							"config_processor: launching new ACL: {}",
							acl_conf );
				} );

		// Create ACL ID seed for a new ACL.
		const auto acl_id_seed = make_next_acl_req_id_seed( m_acl_id_seed );

		// Now the new ACL can be created.
		m_running_acls.emplace_back(
				acl_conf,
				io_thread_index,
				::arataga::acl_handler::introduce_acl_handler(
						so_environment(),
						so_coop(), // We as the parent coop.
						m_io_threads[ io_thread_index ].m_disp.binder(),
						m_app_ctx,
						::arataga::acl_handler::params_t{
								m_io_threads[ io_thread_index ].m_disp.io_context(),
								acl_conf,
								m_io_threads[ io_thread_index ].m_dns_mbox,
								m_io_threads[ io_thread_index ].m_auth_mbox,
								fmt::format( "{}-{}-{}-io_thr_{}-v{}",
										acl_conf.m_protocol,
										acl_conf.m_port,
										acl_conf.m_in_addr,
										io_thread_index,
										m_config_update_counter ),
								acl_id_seed,
								config.m_common_acl_params
						}
				)
		);

		// We should know that this IO-thread holds one more ACL.
		m_io_threads[ io_thread_index ].m_running_acl_count += 1u;

		// Try to switch to another IO-thread.
		// Do that only if the next IO-thread (or the first if the current
		// is the rightmost) holds less ACL than the current IO-thread.
		const auto next_index = (io_thread_index + 1u) % m_io_threads.size();
		if( m_io_threads[ io_thread_index ].m_running_acl_count >
				m_io_threads[ next_index ].m_running_acl_count )
			io_thread_index = next_index;
	}

	// Important: new content of m_running_acls should be sorted
	// the right way.
	std::sort( m_running_acls.begin(), m_running_acls.end(),
			[]( const auto & a, const auto & b ) {
				return port_and_in_addr_less_comparator( a.m_config, b.m_config );
			} );
}

std::size_t
a_processor_t::index_of_io_thread_with_lowest_acl_count() const noexcept
{
	const auto it = std::min_element(
			m_io_threads.begin(), m_io_threads.end(),
			[]( const auto & a, const auto & b ) {
				return a.m_running_acl_count < b.m_running_acl_count;
			} );
	if( it != m_io_threads.end() )
		return static_cast<std::size_t>(
				std::distance( m_io_threads.begin(), it ));
	else
		return 0u;
}

void
a_processor_t::store_new_config_to_file(
	std::string_view content )
{
	try
	{
		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::trace,
				[&]( auto & logger, auto level )
				{
					logger.log(
							level,
							"config_processor: updating local config file {}",
							m_local_config_file_name );
				} );

		std::ofstream file( m_local_config_file_name,
				std::ios_base::out | std::ios_base::binary |
						std::ios_base::trunc );
		if( !file )
			::arataga::utils::ensure_successful_syscall( -1,
					fmt::format( "unable to open local config file {} for "
							"writting", m_local_config_file_name ) );

		file.exceptions( std::ifstream::badbit | std::ifstream::failbit );

		file.write(
				content.data(),
				static_cast<std::streamsize>(content.size()) );

		file.close();
	}
	catch( const std::exception & x )
	{
		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::err,
				[&]( auto & logger, auto level )
				{
					logger.log(
							level,
							"config_processor: error storing new "
							"config into local file {}: {}",
							m_local_config_file_name,
							x.what() );
				} );
	}
}

void
a_processor_t::initiate_debug_auth_processing(
	::arataga::admin_http_entry::replier_shptr_t replier,
	::arataga::admin_http_entry::debug_requests::authentificate_t request )
{
	namespace auth = ::arataga::authentificator;
	namespace http_entry = ::arataga::admin_http_entry;

	// Type of object for sending the response to HTTP-entry.
	class act_t final : public auth::completion_token_t
	{
		http_entry::replier_shptr_t m_replier;

		void
		on_result( const auth::failed_auth_t & v ) const
		{
			m_replier->reply(
					http_entry::status_ok,
					fmt::format( "Failed authentification. Reason: {}\r\n",
							auth::to_string_view( v.m_reason ) )
				);
		}

		void
		on_result( const auth::successful_auth_t & v ) const
		{
			std::string reply;
			reply = fmt::format( "Successful authenitication.\r\n"
					"user_id: {}\r\n"
					"bandlims: {}\r\n",
					v.m_user_id,
					v.m_user_bandlims );

			if( v.m_domain_limits )
				reply += fmt::format( "domain limit ({}): {}\r\n",
						v.m_domain_limits->m_domain,
						v.m_domain_limits->m_bandlims );

			m_replier->reply( http_entry::status_ok, std::move(reply) );
		}

	public:
		act_t( http_entry::replier_shptr_t replier )
			:	m_replier{ replier }
		{}

		void
		complete( const auth::auth_result_t & result ) override
		{
			std::visit(
				[this]( auto && v ) { on_result( v ); },
				result );
		}
	};

	// There should be an ACL to be used as the source of auth request.
	const auto it = std::find_if(
			m_running_acls.begin(), m_running_acls.end(),
			[&]( const auto & racl ) {
				return racl.m_config.m_in_addr == request.m_proxy_in_addr &&
						racl.m_config.m_port == request.m_proxy_port;
			} );
	if( it != m_running_acls.end() )
	{
		// ACL found. The request will be sent to authentificator agent
		// from ACL's IO-thread.
		const so_5::mbox_t auth_mbox =
				m_io_threads.at( it->m_io_thread_index ).m_auth_mbox;

		// Make and fill the request object...
		auto auth_msg = std::make_unique< auth::auth_request_t >();

		// Request ID doesn't matter here.
		auth_msg->m_req_id = auth::auth_req_id_t{ m_own_acl_id_seed, 0u, 0u };
		// Wait the reply on the direct mbox.
		auth_msg->m_reply_to = so_direct_mbox();
		// Our completion token for the request.
		auth_msg->m_completion_token = std::make_shared< act_t >( replier );

		// All other params are copied from the source request.
		auth_msg->m_proxy_in_addr = request.m_proxy_in_addr;
		auth_msg->m_proxy_port = request.m_proxy_port;
		auth_msg->m_user_ip = request.m_user_ip;
		auth_msg->m_username = request.m_username;
		auth_msg->m_password = request.m_password;
		auth_msg->m_target_host = request.m_target_host;
		auth_msg->m_target_port = request.m_target_port;

		// This message should be sent as immutable message,
		// we need message_holder_t for that.
		so_5::send(
				auth_mbox,
				so_5::message_holder_t< auth::auth_request_t >(
						std::move(auth_msg) ) );
	}
	else
	{
		// ACL not found, nothing has to be done.
		replier->reply(
				http_entry::status_bad_request,
				"There is no ACL with the specified parameters\r\n" );
	}
}

void
a_processor_t::initiate_debug_dns_resolve_processing(
	::arataga::admin_http_entry::replier_shptr_t replier,
	::arataga::admin_http_entry::debug_requests::dns_resolve_t request )
{
	namespace dns = ::arataga::dns_resolver;
	namespace forward = ::arataga::dns_resolver::forward;
	namespace http_entry = ::arataga::admin_http_entry;

	// Type of object for sending the response to HTTP-entry.
	class act_t final : public forward::completion_token_t
	{
		http_entry::replier_shptr_t m_replier;

		void
		on_result( const forward::failed_resolve_t & v ) const
		{
			m_replier->reply(
				http_entry::status_ok,
				fmt::format( "Dns resolve failed. Reason: {}\r\n",
					v.m_error_desc )
			);
		}

		void
		on_result( const forward::successful_resolve_t & v ) const
		{
			std::string reply;

			reply = fmt::format( "Successful dns resolve.\r\n"
					"resource address: {}\r\n",
					v.m_address);

			m_replier->reply( http_entry::status_ok, std::move(reply) );
		}

	public:
		act_t( http_entry::replier_shptr_t replier )
			:	m_replier{ replier }
		{}

		void
		complete( const forward::resolve_result_t & result ) override
		{
			std::visit(
				[this]( auto && v ) { on_result( v ); },
				result );
		}
	};

	// There should be an ACL to be used as the source of domain
	// name resolution request.
	const auto it = std::find_if(
		m_running_acls.begin(), m_running_acls.end(),
		[&]( const auto & racl ) {
			return racl.m_config.m_in_addr == request.m_proxy_in_addr &&
					racl.m_config.m_port == request.m_proxy_port;
		} );

	if( it != m_running_acls.end() )
	{
		// ACL found. The request will be sent to the dns_resolver agent
		// from ACL's IO-thread.
		const so_5::mbox_t dns_mbox =
				m_io_threads.at( it->m_io_thread_index ).m_dns_mbox;

		// Create and fill the request object...
		auto dns_msg = std::make_unique< dns::resolve_request_t >();

		// Request ID doesn't matter here.
		dns_msg->m_req_id = dns::resolve_req_id_t{ m_own_acl_id_seed, 0u, 0u };
		// Wait the response on the direct mbox.
		dns_msg->m_reply_to = so_direct_mbox();
		// Our completion token.
		dns_msg->m_completion_token = std::make_shared< act_t >(
			replier );

		// All other parameters are just copied from the source request.
		dns_msg->m_name = request.m_target_host;
		dns_msg->m_ip_version =
			request.m_ip_version.empty()?
				ip_version_t::ip_v4:
				dns::from_string( request.m_ip_version );

		// This message should be sent as immutable message,
		// we need message_holder_t for that.
		so_5::send(
			dns_mbox,
			so_5::message_holder_t< dns::resolve_request_t >(
				std::move(dns_msg) ) );
	}
	else
	{
		// ACL not found, nothing has to be done.
		replier->reply(
				http_entry::status_bad_request,
				"There is no ACL with the specified parameters\r\n" );
	}
}

//
// introduce_config_processor
//
void
introduce_config_processor(
	so_5::environment_t & env,
	so_5::disp_binder_shptr_t disp_binder,
	application_context_t app_ctx,
	params_t params )
{
	env.introduce_coop(
			disp_binder,
			[&]( so_5::coop_t & coop ) {
				coop.make_agent< a_processor_t >(
						std::move(app_ctx),
						std::move(params) );
			} );
}

} /* namespace arataga::config_processor */

