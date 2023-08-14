/*!
 * @file
 * @brief Agent acl_handler.
 */

#include <arataga/acl_handler/a_handler.hpp>

#include <arataga/acl_handler/handler_factories.hpp>

#include <arataga/acl_handler/exception.hpp>

#include <arataga/utils/overloaded.hpp>
#include <arataga/utils/string_literal_fmt.hpp>

#include <arataga/logging/wrap_logging.hpp>

#include <arataga/nothrow_block/macros.hpp>

#include <fmt/format.h>
#include <fmt/ostream.h>
#include <fmt/chrono.h>

using namespace std::chrono_literals;

namespace arataga::acl_handler
{

//
// actual_config_t
//
actual_config_t::actual_config_t(
	const acl_config_t & acl_config,
	const common_acl_params_t & common_acl_params )
	:	m_acl_config{ acl_config }
	,	m_common_acl_params{ common_acl_params }
{}

acl_protocol_t
actual_config_t::acl_protocol() const noexcept
{
	return m_acl_config.m_protocol;
}

const asio::ip::address &
actual_config_t::out_addr() const noexcept
{
	return m_acl_config.m_out_addr;
}

std::size_t
actual_config_t::io_chunk_size() const noexcept
{
	return m_common_acl_params.m_io_chunk_size;
}

std::size_t
actual_config_t::io_chunk_count() const noexcept
{
	return m_common_acl_params.m_io_chunk_count;
}

std::chrono::milliseconds
actual_config_t::protocol_detection_timeout() const noexcept
{
	return m_common_acl_params.m_protocol_detection_timeout;
}

std::chrono::milliseconds
actual_config_t::socks_handshake_phase_timeout() const noexcept
{
	return m_common_acl_params.m_socks_handshake_phase_timeout;
}

std::chrono::milliseconds
actual_config_t::dns_resolving_timeout() const noexcept
{
	return m_common_acl_params.m_dns_resolving_timeout;
}

std::chrono::milliseconds
actual_config_t::authentification_timeout() const noexcept
{
	return m_common_acl_params.m_authentification_timeout;
}

std::chrono::milliseconds
actual_config_t::connect_target_timeout() const noexcept
{
	return m_common_acl_params.m_connect_target_timeout;
}

std::chrono::milliseconds
actual_config_t::socks_bind_timeout() const noexcept
{
	return m_common_acl_params.m_socks_bind_timeout;
}

std::chrono::milliseconds
actual_config_t::idle_connection_timeout() const noexcept
{
	return m_common_acl_params.m_idle_connection_timeout;
}

std::chrono::milliseconds
actual_config_t::http_headers_complete_timeout() const noexcept
{
	return m_common_acl_params.m_http_headers_complete_timeout;
}

std::chrono::milliseconds
actual_config_t::http_negative_response_timeout() const noexcept
{
	return m_common_acl_params.m_http_negative_response_timeout;
}

const http_message_value_limits_t &
actual_config_t::http_message_limits() const noexcept
{
	return m_common_acl_params.m_http_message_limits;
}

//
// actual_traffic_limiter_t
//
/*!
 * @brief Actual traffic limiter for one connection of an
 * authentificated user.
 */
class actual_traffic_limiter_t final : public traffic_limiter_t
{
	// This reference is necessary to decrement the count of connections
	// when traffic_limiter is destroyed (maybe the information about
	// this user will be removed too if it was the last connection).
	authentificated_user_map_t & m_auth_users;

	// Reference to the description of that user.
	authentificated_user_map_t::iterator m_it_auth_user;

	// Reference to the limit for a particular domain (if such limit is set).
	std::optional<
				bandlim_manager_t::domain_traffic_map_t::iterator
			> m_it_domain_traffic;

	// Type of a pointer to a field in channel_limits_data_t.
	using end_member_ptr_t =
			bandlim_manager_t::direction_traffic_info_t
					bandlim_manager_t::channel_limits_data_t::*;

	[[nodiscard]]
	static bandlim_manager_t::direction_traffic_info_t &
	get_reference_to_member(
		end_member_ptr_t member,
		bandlim_manager_t::channel_limits_data_t & channel_limits ) noexcept
	{
		return (channel_limits.*member);
	}

	[[nodiscard]]
	reserved_capacity_t
	detect_max_read_size_for(
		end_member_ptr_t member,
		std::size_t buffer_size ) noexcept
	{
		std::size_t reserved_amount{};

		const auto free_space_or_zero =
			[]( auto quote, auto reserved, auto actual ) {
				const auto spent = reserved + actual;

				return static_cast< std::size_t >(
						spent < *quote ? (*quote - spent) : 0u );
			};

		bandlim_manager_t::direction_traffic_info_t & total_traffic =
				get_reference_to_member(
						member,
						m_it_auth_user->second.m_bandlims.general_traffic() );

		bandlim_manager_t::direction_traffic_info_t * opt_domain_traffic =
				m_it_domain_traffic ?
				  	&(get_reference_to_member(
							member,
							(*m_it_domain_traffic)->second.m_traffic )) 
					: nullptr;

		reserved_amount = free_space_or_zero(
				total_traffic.m_quote,
				total_traffic.m_reserved,
				total_traffic.m_actual );

		if( opt_domain_traffic )
			reserved_amount = std::min(
					reserved_amount,
					free_space_or_zero(
							opt_domain_traffic->m_quote,
							opt_domain_traffic->m_reserved,
							opt_domain_traffic->m_actual )
				);

		reserved_amount = std::min( reserved_amount, buffer_size );

		total_traffic.m_reserved += reserved_amount;
		if( opt_domain_traffic )
			opt_domain_traffic->m_reserved += reserved_amount;

		// Use the fact that sequence numbers are the same
		// for all instances of direction_traffic_info_t.
		return { reserved_amount, total_traffic.m_sequence_number };
	}

	void
	update_counter(
		end_member_ptr_t member,
		reserved_capacity_t reserved_capacity,
		std::size_t bytes ) noexcept
	{
		const auto bytes_to_release = reserved_capacity.m_capacity;

		{
			auto & traffic = get_reference_to_member(
					member,
					m_it_auth_user->second.m_bandlims.general_traffic() );
			traffic.m_actual += bytes;
			auto & reserved = traffic.m_reserved;
			if( reserved_capacity.m_sequence_number == traffic.m_sequence_number
					// We don't expect that value of `reserved` will be less
					// that `bytes_to_release` on the same turn.
					// But it better to play it safe to avoid underflow.
					&& reserved >= bytes_to_release )
			{
				reserved -= bytes_to_release;
			}
		}

		if( m_it_domain_traffic )
		{
			auto & traffic = get_reference_to_member(
					member,
					(*m_it_domain_traffic)->second.m_traffic );
			traffic.m_actual += bytes;
			auto & reserved = traffic.m_reserved;
			if( reserved_capacity.m_sequence_number == traffic.m_sequence_number
					// We don't expect that value of `reserved` will be less
					// that `bytes_to_release` on the same tick.
					// But it better to play it safe to avoid underflow.
					&& reserved >= bytes_to_release )
			{
				reserved -= bytes_to_release;
			}
		}
	}

public:
	actual_traffic_limiter_t(
		authentificated_user_map_t & auth_users,
		authentificated_user_map_t::iterator it_auth_user,
		std::optional<
					bandlim_manager_t::domain_traffic_map_t::iterator
				> it_domain_traffic )
		:	m_auth_users{ auth_users }
		,	m_it_auth_user{ it_auth_user }
		,	m_it_domain_traffic{ std::move(it_domain_traffic) }
	{}

	~actual_traffic_limiter_t() override
	{
		auto & user_info = m_it_auth_user->second;

		if( m_it_domain_traffic )
		{
			user_info.m_bandlims.connection_removed( *m_it_domain_traffic );
		}

		user_info.m_connection_count -= 1u;
		if( !user_info.m_connection_count )
			m_auth_users.erase( m_it_auth_user );
	}

	reserved_capacity_t
	reserve_read_portion(
		direction_t dir,
		std::size_t buffer_size ) noexcept override
	{
		reserved_capacity_t result;
		switch( dir )
		{
		case direction_t::from_user:
			result = detect_max_read_size_for(
				&bandlim_manager_t::channel_limits_data_t::m_user_end_traffic,
				buffer_size );
		break;
		
		case direction_t::from_target:
			result = detect_max_read_size_for(
				&bandlim_manager_t::channel_limits_data_t::m_target_end_traffic,
				buffer_size );
		break;
		}

		return result;
	}

	void
	release_reserved_capacity( direction_t dir,
		reserved_capacity_t reserved_capacity,
		std::size_t bytes ) noexcept override
	{
		switch( dir )
		{
		case direction_t::from_user:
			update_counter(
					&bandlim_manager_t::channel_limits_data_t::m_user_end_traffic,
					reserved_capacity,
					bytes );
		break;

		case direction_t::from_target:
			update_counter(
					&bandlim_manager_t::channel_limits_data_t::m_target_end_traffic,
					reserved_capacity,
					bytes );
		break;
		}
	}
};

//
// a_handler_t
//
a_handler_t::a_handler_t(
	context_t ctx,
	application_context_t app_ctx,
	params_t params )
	:	so_5::agent_t{ std::move(ctx) }
	,	m_app_ctx{ std::move(app_ctx) }
	,	m_params{ std::move(params) }
	,	m_acl_stats_reg{
			m_app_ctx.m_acl_stats_manager,
			m_acl_stats
		}
	,	m_current_common_acl_params{ m_params.m_common_acl_params }
	,	m_connection_handlers_config{
			m_params.m_acl_config,
			m_current_common_acl_params
		}
	,	m_acceptor{ m_params.m_io_ctx }
{}

a_handler_t::~a_handler_t()
{
	::arataga::logging::direct_mode::trace(
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: destroyed", m_params.m_name );
			} );
}

void
a_handler_t::so_define_agent()
{
	this >>= st_basic;

	st_basic
		.event( &a_handler_t::on_shutdown )
		.event( m_app_ctx.m_config_updates_mbox,
				&a_handler_t::on_updated_config )
		;

	st_entry_not_created
		.event( &a_handler_t::on_try_create_entry_point );

	st_entry_created
		.on_enter( &a_handler_t::on_enter_st_entry_created )
		.event( &a_handler_t::on_dns_result )
		.event( &a_handler_t::on_auth_result )
		;

	st_accepting
		.on_enter( &a_handler_t::on_enter_st_accepting )
		.event( &a_handler_t::on_accept_next_when_accepting )
		.event( &a_handler_t::on_accept_completion_when_accepting );

	st_too_many_connections
		.on_enter( [this]() {
				// Too many connections accepted. This fact has to be logged.
				::arataga::logging::direct_mode::warn(
						[&]( auto & logger, auto level )
						{
							logger.log(
									level,
									"{}: pausing the acception of "
										"new connections (current count: {}, "
										"allowed limit: {})",
									m_params.m_name,
									m_connections.size(),
									m_current_common_acl_params.m_maxconn );
						} );
			} )
		.just_switch_to< enable_accepting_connections_t >( st_accepting );
}

void
a_handler_t::so_evt_start()
{
	::arataga::logging::direct_mode::info(
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: created, acl_id_seed: {}",
						m_params.m_name,
						m_params.m_acl_id_seed );
			} );

	so_5::send< try_create_entry_point_t >( *this );
}

void
a_handler_t::so_evt_finish()
{
	::arataga::logging::direct_mode::info(
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: shutdown completed", m_params.m_name );
			} );

	// Cleanup all sockets.
	m_acceptor.close();
	m_connections.clear();

	// Deactivate timer if activated.
	m_params.m_timer_provider.deactivate_consumer( *this );
}

void
a_handler_t::replace_connection_handler(
	connection_id_t id,
	connection_handler_shptr_t handler )
{
	auto & info = connection_info_that_must_be_present( id );

	auto old_handler = info.replace( std::move(handler) );

	::arataga::logging::direct_mode::trace(
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: connection {}: handler changed, old={}, new={}",
						m_params.m_name,
						make_long_id(id),
						old_handler->name(),
						info.handler()->name() );
			} );

	// The new handler should be started.
	// NOTE: during that call the handler can be changed yet again.
	info.handler()->on_start();
}

void
a_handler_t::remove_connection_handler(
	connection_id_t id,
	remove_reason_t reason ) noexcept
{
	auto it = m_connections.find( id );
	if( it != m_connections.end() )
	{
		m_connections.erase( it );

		update_remove_handle_stats( reason );

		// Do not catch exceptions because if an exception is thrown
		// then we have to chances to recover.
		::arataga::logging::direct_mode::debug(
				[&]( auto & logger, auto level )
				{
					logger.log(
							level,
							"{}: connection {} removed ({}), connections: {}/{}",
							m_params.m_name,
							make_long_id(id),
							fmt::streamed(reason),
							m_connections.size(),
							m_current_common_acl_params.m_maxconn );
				} );

		try_switch_to_accepting_if_necessary_and_possible();
	}

	// Maybe there is no more live handlers and timers have to be
	// deactivated.
	if( m_connections.empty() )
		m_params.m_timer_provider.deactivate_consumer( *this );
}

void
a_handler_t::log_message_for_connection(
	connection_id_t id,
	::arataga::logging::processed_log_level_t level,
	std::string_view message )
{
	// Don't use wrap_logging because this method is called from inside
	// of wrap_logging call.
	::arataga::logging::impl::logger().log(
			level,
			"{}: connection {} => {}",
			m_params.m_name,
			make_long_id(id),
			message );
}

[[nodiscard]]
const config_t &
a_handler_t::config() const noexcept
{
	return m_connection_handlers_config;
}

void
a_handler_t::async_resolve_hostname(
	connection_id_t connection_id,
	const std::string & hostname,
	dns_resolving::hostname_result_handler_t result_handler )
{
	namespace dnsr = ::arataga::dns_resolver;

	// Own completion-token for calling the
	// hostname-result-handler received from connection_handler.
	class token_t final : public dnsr::forward::completion_token_t
	{
		dns_resolving::hostname_result_handler_t m_handler;

	public:
		token_t(
			dns_resolving::hostname_result_handler_t handler )
			:	m_handler{ std::move(handler) }
		{}

		void
		complete( const dnsr::forward::resolve_result_t & result ) override
		{
			m_handler( std::visit( ::arataga::utils::overloaded{
					[]( const dnsr::forward::failed_resolve_t & info )
					-> dns_resolving::hostname_result_t
					{
						return dns_resolving::hostname_not_found_t{
								info.m_error_desc
							};
					},
					[]( const dnsr::forward::successful_resolve_t & info )
					-> dns_resolving::hostname_result_t
					{
						return dns_resolving::hostname_found_t{
								info.m_address
							};
					}
				},
				result ) );
		}
	};

	// Use ID of connection as ID for DNS-resolver request.
	// That ID will be unqiue for the ACL.
	const auto id = make_long_id( connection_id );

	::arataga::logging::direct_mode::trace(
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: initiate DNS resolve for '{}' with id {}",
						m_params.m_name,
						hostname,
						id );
			} );

	const auto ip_version_for_result =
			m_params.m_acl_config.m_out_addr.is_v4() ?
					ip_version_t::ip_v4 : ip_version_t::ip_v6;

	so_5::send< dnsr::resolve_request_t >( m_params.m_dns_mbox,
			id,
			hostname,
			ip_version_for_result,
			std::make_shared< token_t >( std::move(result_handler) ),
			so_direct_mbox() );
}

void
a_handler_t::async_authentificate(
	connection_id_t connection_id,
	authentification::request_params_t request,
	authentification::result_handler_t result_handler )
{
	namespace auth_ns = ::arataga::authentificator;

	using post_auth_hook_t =
			traffic_limiter_unique_ptr_t (a_handler_t::*)(
					const auth_ns::successful_auth_t &);

	// Own completion-token that calls result-handler
	// provided by connection_handler.
	class token_t final : public auth_ns::completion_token_t
	{
		a_handler_t & m_agent;
		post_auth_hook_t m_post_auth_hook;
		authentification::result_handler_t m_handler;

		[[nodiscard]]
		static authentification::failure_reason_t
		convert_reason( auth_ns::failure_reason_t original )
		{
			switch( original )
			{
				case auth_ns::failure_reason_t::unknown_user:
					return authentification::failure_reason_t::unknown_user;

				case auth_ns::failure_reason_t::target_blocked: /*[[fallthrough]]*/
				case auth_ns::failure_reason_t::auth_operation_timedout:
				break;
			}

			return authentification::failure_reason_t::target_blocked;
		}

	public:
		token_t(
			a_handler_t & agent,
			post_auth_hook_t post_auth_hook,
			authentification::result_handler_t handler )
			:	m_agent{ agent }
			,	m_post_auth_hook{ post_auth_hook }
			,	m_handler{ std::move(handler) }
		{}

		void
		complete( const auth_ns::auth_result_t & result ) override
		{
			m_handler( std::visit( ::arataga::utils::overloaded{
					[]( const auth_ns::failed_auth_t & info )
					-> authentification::result_t
					{
						return authentification::failure_t{
								convert_reason( info.m_reason )
							};
					},
					[this]( const auth_ns::successful_auth_t & info )
					-> authentification::result_t
					{
						return authentification::success_t{
								(m_agent.*m_post_auth_hook)( info )
						};
					}
				},
				result ) );
		}
	};

	const auto id = make_long_id( connection_id );

	::arataga::logging::direct_mode::trace(
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: initiate authentification with id {}",
						m_params.m_name,
						id );
			} );

	auto req = std::make_unique< auth_ns::auth_request_t >();

	req->m_req_id = id;
	req->m_reply_to = so_direct_mbox();
	req->m_completion_token = std::make_shared< token_t >(
			*this,
			&a_handler_t::user_authentificated,
			std::move(result_handler) );

	req->m_proxy_in_addr = m_params.m_acl_config.m_in_addr;
	req->m_proxy_port = m_params.m_acl_config.m_port;

	req->m_user_ip = request.m_user_ip;
	req->m_username = std::move(request.m_username);
	req->m_password = std::move(request.m_password);

	req->m_target_host = std::move(request.m_target_host);
	req->m_target_port = request.m_target_port;

	so_5::send( m_params.m_auth_mbox,
			so_5::message_holder_t< auth_ns::auth_request_t >{
					std::move(req)
			} );
}

void
a_handler_t::stats_inc_connection_count(
	connection_type_t connection_type )
{
	switch( connection_type )
	{
		case connection_type_t::generic:
			m_acl_stats.m_total_connections += 1u;
		break;

		case connection_type_t::http:
			m_acl_stats.m_http_connections += 1u;
		break;

		case connection_type_t::socks5:
			m_acl_stats.m_socks5_connections += 1u;
		break;
	}
}

void
a_handler_t::on_timer() noexcept
{
	ARATAGA_NOTHROW_BLOCK_BEGIN()
		ARATAGA_NOTHROW_BLOCK_STAGE(update_traffic_limit_quotes)

		// Start a new turn. Traffic quotes have to be recalculated.
		update_traffic_limit_quotes_on_new_turn();

		ARATAGA_NOTHROW_BLOCK_STAGE(call_on_timer_for_connection_handlers)

		// Additional care should be taken with iterators because
		// the content of m_connections can be changed right inside
		// on_timer call.
		for( auto it = m_connections.begin(); it != m_connections.end(); )
		{
			// Hold a pointer until on_timer will be completed.
			auto handler = it->second.handler();
			++it; // Go to next item before the call to on_timer.

			handler->on_timer();
		}
	ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_ABORT)
}

void
a_handler_t::on_shutdown( mhood_t< shutdown_t > )
{
	::arataga::logging::direct_mode::debug(
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: shutting down...", m_params.m_name );
			} );

	// Switch a special state to avoid handling of any events.
	this >>= st_shutting_down;

	// This coop has to be destroyed.
	so_deregister_agent_coop_normally();
}

void
a_handler_t::on_try_create_entry_point(
	mhood_t< try_create_entry_point_t > )
{
	asio::error_code ec;

	const asio::ip::tcp::acceptor::endpoint_type endpoint{
			m_params.m_acl_config.m_in_addr,
			m_params.m_acl_config.m_port
	};

	::arataga::logging::direct_mode::info(
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: trying to open an entry on endpoint {}...",
						m_params.m_name,
						fmt::streamed(endpoint) );
			} );

	// Use a temporary instance of `acceptor` type.
	// This instance will be moved into `m_acceptor` if everything
	// will be OK.
	asio::ip::tcp::acceptor tmp_acceptor{ m_params.m_io_ctx };

	// Helper function to avoid writting nested `if-else` statements.
	const auto finish_on_failure = [this]( auto && ...log_params ) -> void {
		// All problems related to impossibility of create/tune the acceptor
		// should be logged as critical.
		::arataga::logging::direct_mode::critical(
				[&]( auto & logger, auto level )
				{
					logger.log(
							level,
							std::forward<decltype(log_params)>(log_params)... );
				} );

		// We have to repeat after some time-out.
		so_5::send_delayed< try_create_entry_point_t >( *this,
				// This is just an arbitrary value for the very first version.
				10s );
	};

	tmp_acceptor.open( endpoint.protocol(), ec );
	if( ec )
	{
		return finish_on_failure(
				fmt::runtime( "{}: unable to open acceptor: {}" ),
				m_params.m_name,
				ec.message() );
	}

	tmp_acceptor.non_blocking( true, ec );
	if( ec )
	{
		return finish_on_failure(
				fmt::runtime( "{}: unable to turn non-blocking mode on acceptor: {}" ),
				m_params.m_name,
				ec.message() );
	}

	tmp_acceptor.set_option(
			asio::ip::tcp::acceptor::reuse_address( true ), ec );
	if( ec )
	{
		return finish_on_failure(
				fmt::runtime( "{}: unable to sent REUSEADDR option: {}" ),
				m_params.m_name,
				ec.message() );
	}

	tmp_acceptor.bind( endpoint, ec );
	if( ec )
	{
		return finish_on_failure(
				fmt::runtime( "{}: unable to bind acceptor to endpoint {}: {}" ),
				m_params.m_name,
				fmt::streamed(endpoint),
				ec.message() );
	}

	tmp_acceptor.listen(
			// This is just an arbitrary value for the very first version.
			10,
			ec );
	if( ec )
	{
		return finish_on_failure(
				fmt::runtime( "{}: call to acceptor's listen failed: {}" ),
				m_params.m_name,
				ec.message() );
	}

	// Now we can go to the normal mode.
	m_acceptor = std::move(tmp_acceptor);
	this >>= st_entry_created;
}

void
a_handler_t::on_enter_st_entry_created() noexcept
{
}

void
a_handler_t::on_enter_st_accepting() noexcept
{
	::arataga::logging::direct_mode::debug(
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: resuming the acception of "
							"new connections (current count: {}, allowed limit: {})",
						m_params.m_name,
						m_connections.size(),
						m_current_common_acl_params.m_maxconn );
			} );

	// There is not sense to continue if this `send` throws.
	so_5::send< accept_next_t >( *this );
}

void
a_handler_t::on_accept_next_when_accepting( mhood_t< accept_next_t > )
{
	::arataga::logging::direct_mode::debug(
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: accepting new connection",
						m_params.m_name );
			} );

	// Do not wait exceptions here.
	// There is no sense to continue if this call throws.
	m_acceptor.async_accept(
			[self = so_5::make_agent_ref(this)](
				const asio::error_code & ec,
				asio::ip::tcp::socket connection )
			{
				if( ec )
				{
					// Ignore operation_aborted because it's expected
					// during the shutdown operation.
					if( asio::error::operation_aborted != ec )
						::arataga::logging::direct_mode::err(
								[&]( auto & logger, auto level )
								{
									logger.log(
											level,
											"{}: async_accept failure: {}",
											self->m_params.m_name,
											ec.message() );
								} );
				}
				else
				{
					self->accept_new_connection( std::move(connection) );
				}

				so_5::send< current_accept_completed_t >( *self );
			} );
}

void
a_handler_t::on_accept_completion_when_accepting(
	mhood_t< current_accept_completed_t > )
{
	if( m_connections.size() < m_current_common_acl_params.m_maxconn )
		so_5::send< accept_next_t >( *this );
	else
		// Should go to the state where new connections are not accepted.
		this >>= st_too_many_connections;
}

void
a_handler_t::on_dns_result(
	mhood_t< ::arataga::dns_resolver::resolve_reply_t > cmd )
{
	::arataga::logging::direct_mode::trace(
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: reply from DNS resolve for req_id {}: {}",
						m_params.m_name,
						cmd->m_req_id,
						fmt::streamed(cmd->m_result) );
			} );

	// Should find a connection that issued this request.
	// This connection can be non-existent as this time.
	// In that case we can just ignore the result.
	if( auto * const connection_info = try_find_connection_info(
			cmd->m_req_id.m_id ) )
	{
		// The connection still exists, so the result should be handled.
		cmd->m_completion_token->complete( cmd->m_result );
	}
}

void
a_handler_t::on_auth_result(
	mhood_t< ::arataga::authentificator::auth_reply_t > cmd )
{
	::arataga::logging::direct_mode::trace(
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: reply from authentificator for req_id {}: {}",
						m_params.m_name,
						cmd->m_req_id,
						fmt::streamed(cmd->m_result) );
			} );

	// Should find a connection that issued this request.
	// This connection can be non-existent as this time.
	// In that case we can just ignore the result.
	if( auto * const connection_info = try_find_connection_info(
			cmd->m_req_id.m_id ) )
	{
		// The connection still exists, so the result should be handled.
		cmd->m_completion_token->complete( cmd->m_result );
	}
}

void
a_handler_t::on_updated_config(
	mhood_t< ::arataga::config_processor::updated_common_acl_params_t > cmd )
{
	m_current_common_acl_params = cmd->m_params;

	// Limits for all bandlim_managers should be updated.
	update_default_bandlims_on_confg_change();

	// If we are in st_accepting then there is no need to do anything,
	// even if maxconn is less than the current connection count.
	// It is because we'll automatically do a check after the
	// return from `accept`. And will go to st_too_many_connections
	// from st_accepting.
	//
	// But if we are in st_too_many_connections then it is necessary
	// to check the possibility to return to st_accepting.
	try_switch_to_accepting_if_necessary_and_possible();
}

a_handler_t::connection_info_t &
a_handler_t::connection_info_that_must_be_present(
	connection_id_t id )
{
	auto * info = try_find_connection_info( id );
	if( !info )
		throw acl_handler_ex_t{
				fmt::format( "{}: unknown connection id: {}",
						m_params.m_name,
						id )
			};

	return *info;
}

[[nodiscard]]
a_handler_t::connection_info_t *
a_handler_t::try_find_connection_info(
	connection_id_t id )
{
	auto it = m_connections.find( id );
	return it == m_connections.end() ? nullptr : &(it->second);
}

void
a_handler_t::accept_new_connection(
	asio::ip::tcp::socket connection ) noexcept
{
	ARATAGA_NOTHROW_BLOCK_BEGIN()

	// A new ID for the new connection.
	const auto id = ++m_connection_id_counter;

	ARATAGA_NOTHROW_BLOCK_STAGE(log_info_about_new_connection)

	::arataga::logging::direct_mode::debug(
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: new connection {} accepted from {}",
						m_params.m_name,
						make_long_id(id),
						fmt::streamed(connection.remote_endpoint()) );
			} );

	ARATAGA_NOTHROW_BLOCK_STAGE(switch_new_socket_to_non_blocking_mode)

	asio::error_code ec;
	connection.non_blocking( true, ec );
	if( ec )
	{
		::arataga::logging::direct_mode::err(
				[&]( auto & logger, auto level )
				{
					logger.log(
							level,
							"{}: unable to switch socket to "
							"non-blocking mode for {}: {}; connection will be closed",
							m_params.m_name,
							make_long_id(id),
							ec.message() );
				} );

		return;
	}

	ARATAGA_NOTHROW_BLOCK_STAGE(make_protocol_detection_handler)

	// Initial handler for the new connection.
	connection_handler_shptr_t handler = make_protocol_detection_handler(
			handler_context_holder_t{ so_5::make_agent_ref(this), *this },
			id,
			std::move(connection) );

	// Create an instance of connection_info_t to hold the new handler.
	// This instance is necessary for correct deletion of the new handler
	// in the case of an exception.
	connection_info_t new_connection_info{ std::move(handler) };

	ARATAGA_NOTHROW_BLOCK_STAGE(call_new_handler_on_start)

	// This handler should be started manually.
	new_connection_info.handler()->on_start();

	ARATAGA_NOTHROW_BLOCK_STAGE(store_new_handler_to_connections_map)

	// If there were no connections then timer has to be activated
	// after accepting new connection.
	//
	// NOTE: activate_consumer() is called before emplace().
	// If activate_consumer() throws then we shouldn't remove
	// connection_info from m_connections.
	if( m_connections.empty() )
		m_params.m_timer_provider.activate_consumer( *this );

	// New connection has to be stored in the list of known connections.
	m_connections.emplace( id, std::move(new_connection_info) );

	ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_IGNORE)
}

void
a_handler_t::update_default_bandlims_on_confg_change() noexcept
{
	for( auto & [id, info] : m_authentificated_users )
	{
		info.m_bandlims.update_default_limits(
				m_current_common_acl_params.m_client_bandlim );
	}
}

void
a_handler_t::update_traffic_limit_quotes_on_new_turn()
{
	if( !m_authentificated_users.empty() )
	{
		for( auto & [id, info] : m_authentificated_users )
			info.m_bandlims.update_traffic_counters_for_new_turn();
	}
}

traffic_limiter_unique_ptr_t
a_handler_t::user_authentificated(
	const ::arataga::authentificator::successful_auth_t & info )
{
	// If there is no info about this user that info should be created.
	auto it = m_authentificated_users.find( info.m_user_id );
	if( it == m_authentificated_users.end() )
	{
		it = m_authentificated_users.emplace(
				info.m_user_id,
				authentificated_user_info_t{
						// The current connection from the user is taken
						// into account.
						1u,
						bandlim_manager_t{
								info.m_user_bandlims,
								m_current_common_acl_params.m_client_bandlim
						}
				} ).first;
	}
	else
	{
		// A new connection should be taken into account.
		it->second.m_connection_count += 1u;

		// The personal limit for the user could has been changed.
		// This case should be reflected in bandlim_manager.
		it->second.m_bandlims.update_personal_limits(
				info.m_user_bandlims,
				m_current_common_acl_params.m_client_bandlim );
	}

	std::optional< bandlim_manager_t::domain_traffic_map_t::iterator >
			it_domain_traffic;

	if( info.m_domain_limits )
	{
		// There are individual limits for the domain and
		// this should be taken into account.
		it_domain_traffic = it->second.m_bandlims.make_domain_limits(
				info.m_domain_limits->m_domain,
				info.m_domain_limits->m_bandlims );
	}

	return std::make_unique< actual_traffic_limiter_t >(
			m_authentificated_users,
			it,
			it_domain_traffic
		);
}

::arataga::utils::acl_req_id_t
a_handler_t::make_long_id( connection_id_t id ) const noexcept
{
	return { m_params.m_acl_id_seed, m_params.m_acl_config.m_port, id };
}

void
a_handler_t::try_switch_to_accepting_if_necessary_and_possible()
{
	// Normal work can't be continued if so_5::send() throws and
	// enable_accepting_connections_t won't be sent.
	// This case has to be logged and the application has to be terminated.
	ARATAGA_NOTHROW_BLOCK_BEGIN()

	// If we have stopped the acceptance of new connections but the
	// current count of connection dropped below maxconn then
	// we can resume the acception of new connection.
	if( st_too_many_connections.is_active() &&
			m_connections.size() < m_current_common_acl_params.m_maxconn )
	{
		ARATAGA_NOTHROW_BLOCK_STAGE(sending_enable_acception_connections_signal)

		// We can't just change our state because this method is being
		// called from outside of any event-handlers.
		so_5::send< enable_accepting_connections_t >( *this );
	}

	ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_ABORT)
}

void
a_handler_t::update_remove_handle_stats( remove_reason_t reason ) noexcept
{
	switch( reason )
	{
		case remove_reason_t::normal_completion:
			m_acl_stats.m_remove_reason_normal_completion += 1u;
		break;

		case remove_reason_t::io_error:
			m_acl_stats.m_remove_reason_io_error += 1u;
		break;

		case remove_reason_t::current_operation_timed_out:
			m_acl_stats.m_remove_reason_current_operation_timed_out += 1u;
		break;

		case remove_reason_t::unsupported_protocol:
			m_acl_stats.m_remove_reason_unsupported_protocol += 1u;
		break;

		case remove_reason_t::protocol_error:
			m_acl_stats.m_remove_reason_protocol_error += 1u;
		break;

		case remove_reason_t::unexpected_and_unsupported_case:
			m_acl_stats.m_remove_reason_unexpected_error += 1u;
		break;

		case remove_reason_t::no_activity_for_too_long:
			m_acl_stats.m_remove_reason_no_activity_for_too_long += 1u;
		break;

		case remove_reason_t::current_operation_canceled:
			m_acl_stats.m_remove_reason_current_operation_canceled += 1u;
		break;

		case remove_reason_t::unhandled_exception:
			m_acl_stats.m_remove_reason_unhandled_exception += 1u;
		break;

		case remove_reason_t::ip_version_mismatch:
			m_acl_stats.m_remove_reason_ip_version_mismatch += 1u;
		break;

		case remove_reason_t::access_denied:
			m_acl_stats.m_remove_reason_access_denied += 1u;
		break;

		case remove_reason_t::unresolved_target:
			m_acl_stats.m_remove_reason_unresolved_target += 1u;
		break;

		case remove_reason_t::target_end_broken:
			m_acl_stats.m_remove_reason_target_end_broken += 1u;
		break;

		case remove_reason_t::user_end_broken:
			m_acl_stats.m_remove_reason_user_end_broken += 1u;
		break;

		case remove_reason_t::http_response_before_completion_of_http_request:
			m_acl_stats.m_remove_reason_early_http_response += 1u;
		break;

		case remove_reason_t::user_end_closed_by_client:
			m_acl_stats.m_remove_reason_user_end_closed_by_client += 1u;
		break;

		case remove_reason_t::http_no_incoming_request:
			m_acl_stats.m_remove_reason_http_no_incoming_request += 1u;
		break;
	}
}

//
// introduce_acl_handler
//
so_5::mbox_t
introduce_acl_handler(
	so_5::environment_t & env,
	so_5::coop_handle_t parent_coop,
	so_5::disp_binder_shptr_t disp_binder,
	application_context_t app_ctx,
	params_t params )
{
	so_5::mbox_t acl_mbox;

	auto coop_holder = env.make_coop( parent_coop, std::move(disp_binder) );
	acl_mbox = coop_holder->make_agent< a_handler_t >(
			std::move(app_ctx),
			std::move(params) )->so_direct_mbox();

	env.register_coop( std::move(coop_holder) );

	return acl_mbox;
}

} /* namespace arataga::acl_handler */

