/*!
 * @file
 * @brief Agent for collecting arataga's stats.
 */

#include <arataga/stats_collector/a_stats_collector.hpp>

#include <arataga/logging/stats_counters.hpp>

#include <fmt/ostream.h>

#include <sstream>

namespace arataga::stats_collector
{

namespace {

template< typename Atomic >
[[nodiscard]]
auto
value_of( const Atomic & from )
{
	return from.load( std::memory_order_acquire );
}

} /* namespace anonymous */

//
// a_stats_collector_t
//
a_stats_collector_t::a_stats_collector_t(
	context_t ctx,
	application_context_t app_ctx )
	:	so_5::agent_t{ std::move(ctx) }
	,	m_app_ctx{ std::move(app_ctx) }
{}

void
a_stats_collector_t::so_define_agent()
{
	so_subscribe( m_app_ctx.m_stats_collector_mbox )
		.event( &a_stats_collector_t::on_get_current_stats )
		;
}

void
a_stats_collector_t::on_get_current_stats(
	mhood_t< get_current_stats_t > cmd )
{
	std::ostringstream ss;

	{
		format_connection_stats( ss, get_current_connections_stats() );
	}

	{
		const auto auth_stats = get_current_auth_stats();
		fmt::print( ss,
				"AUTH_TOTAL: {}\r\n"
				"AUTH_BY_IP: {}\r\n"
				"AUTH_BY_LOGIN: {}\r\n"
				"REJECT_BY_INVALID_IP: {}\r\n"
				"REJECT_BY_INVALID_LOGIN: {}\r\n"
				"REJECT_BY_DENIED_PORT: {}\r\n",
				auth_stats.m_auth_total_count,
				auth_stats.m_auth_by_ip_count,
				auth_stats.m_auth_by_login_count,
				auth_stats.m_failed_auth_by_ip_count,
				auth_stats.m_failed_auth_by_login_count,
				auth_stats.m_failed_authorization_denied_port );
	}

	{
		const auto dns_stats = get_current_dns_stats();
		fmt::print( ss,
				"DNS_CACHE_HITS: {}\r\n"
				"DNS_SUCCESSFUL_LOOKUPS: {}\r\n"
				"DNS_FAILED_LOOKUPS: {}\r\n",
				dns_stats.m_dns_cache_hits,
				dns_stats.m_dns_successful_lookups,
				dns_stats.m_dns_failed_lookups );
	}

	{
		const auto & cnts = ::arataga::logging::counters();

		fmt::print( ss,
				"LOG_MSG_TRACE: {}\r\n"
				"LOG_MSG_DEBUG: {}\r\n"
				"LOG_MSG_INFO: {}\r\n"
				"LOG_MSG_WARN: {}\r\n"
				"LOG_MSG_ERROR: {}\r\n"
				"LOG_MSG_CRIT: {}\r\n",
				value_of( cnts.m_level_trace_count ),
				value_of( cnts.m_level_debug_count ),
				value_of( cnts.m_level_info_count ),
				value_of( cnts.m_level_warn_count ),
				value_of( cnts.m_level_error_count ),
				value_of( cnts.m_level_critical_count )
			);
	}

	cmd->m_replier->reply(
			::arataga::admin_http_entry::status_ok,
			ss.str() );
}

[[nodiscard]]
a_stats_collector_t::connections_stats_t
a_stats_collector_t::get_current_connections_stats() const
{
	using namespace ::arataga::stats::connections;

	connections_stats_t result{};

	auto collector = lambda_as_enumerator(
		[&result]( const auto & acl_stats ) noexcept {
			using dest_t = decltype(&connections_stats_t::m_total_connections);
			using src_t = decltype(&acl_stats_t::m_total_connections);
			using ptr_pair_t = std::pair<dest_t, src_t>;

			static constexpr std::initializer_list<ptr_pair_t> ptr_pairs{
				std::pair(
						&connections_stats_t::m_total_connections,
						&acl_stats_t::m_total_connections ),
				std::pair(
						&connections_stats_t::m_http_connections,
						&acl_stats_t::m_http_connections ),
				std::pair(
						&connections_stats_t::m_socks5_connections,
						&acl_stats_t::m_socks5_connections ),
				std::pair(
						&connections_stats_t::m_remove_reason_normal_completion,
						&acl_stats_t::m_remove_reason_normal_completion ),
				std::pair(
						&connections_stats_t::m_remove_reason_io_error,
						&acl_stats_t::m_remove_reason_io_error ),
				std::pair(
						&connections_stats_t::m_remove_reason_current_operation_timed_out,
						&acl_stats_t::m_remove_reason_current_operation_timed_out ),
				std::pair(
						&connections_stats_t::m_remove_reason_unsupported_protocol,
						&acl_stats_t::m_remove_reason_unsupported_protocol ),
				std::pair(
						&connections_stats_t::m_remove_reason_protocol_error,
						&acl_stats_t::m_remove_reason_protocol_error ),
				std::pair(
						&connections_stats_t::m_remove_reason_unexpected_error,
						&acl_stats_t::m_remove_reason_unexpected_error ),
				std::pair(
						&connections_stats_t::m_remove_reason_no_activity_for_too_long,
						&acl_stats_t::m_remove_reason_no_activity_for_too_long ),
				std::pair(
						&connections_stats_t::m_remove_reason_current_operation_canceled,
						&acl_stats_t::m_remove_reason_current_operation_canceled ),
				std::pair(
						&connections_stats_t::m_remove_reason_unhandled_exception,
						&acl_stats_t::m_remove_reason_unhandled_exception ),
				std::pair(
						&connections_stats_t::m_remove_reason_ip_version_mismatch,
						&acl_stats_t::m_remove_reason_ip_version_mismatch ),
				std::pair(
						&connections_stats_t::m_remove_reason_access_denied,
						&acl_stats_t::m_remove_reason_access_denied ),
				std::pair(
						&connections_stats_t::m_remove_reason_unresolved_target,
						&acl_stats_t::m_remove_reason_unresolved_target ),
				std::pair(
						&connections_stats_t::m_remove_reason_target_end_broken,
						&acl_stats_t::m_remove_reason_target_end_broken ),
				std::pair(
						&connections_stats_t::m_remove_reason_user_end_broken,
						&acl_stats_t::m_remove_reason_user_end_broken ),
				std::pair(
						&connections_stats_t::m_remove_reason_early_http_response,
						&acl_stats_t::m_remove_reason_early_http_response ),
				std::pair(
						&connections_stats_t::m_remove_reason_user_end_closed_by_client,
						&acl_stats_t::m_remove_reason_user_end_closed_by_client ),
				std::pair(
						&connections_stats_t::m_remove_reason_http_no_incoming_request,
						&acl_stats_t::m_remove_reason_http_no_incoming_request )

			};

			for( const auto & [d, s] : ptr_pairs )
			{
				(result.*d) += value_of( (acl_stats.*s) );
			}

			return acl_stats_enumerator_t::go_next;
		} );

	m_app_ctx.m_acl_stats_manager->enumerate( collector );

	return result;
}

[[nodiscard]]
a_stats_collector_t::auth_stats_t
a_stats_collector_t::get_current_auth_stats() const
{
	using namespace ::arataga::stats::auth;

	auth_stats_t result{};

	auto collector = lambda_as_enumerator(
			[&result]( const auto & auth_stats ) noexcept {
				result.m_auth_total_count += value_of(
						auth_stats.m_auth_total_count );

				result.m_auth_by_ip_count += value_of(
						auth_stats.m_auth_by_ip_count );

				result.m_failed_auth_by_ip_count += value_of(
						auth_stats.m_failed_auth_by_ip_count );

				result.m_auth_by_login_count += value_of(
						auth_stats.m_auth_by_login_count );

				result.m_failed_auth_by_login_count += value_of(
						auth_stats.m_failed_auth_by_login_count );

				result.m_failed_authorization_denied_port += value_of(
						auth_stats.m_failed_authorization_denied_port );

				return auth_stats_enumerator_t::go_next;
			} );

	m_app_ctx.m_auth_stats_manager->enumerate( collector );

	return result;
}

[[nodiscard]]
a_stats_collector_t::dns_stats_t
a_stats_collector_t::get_current_dns_stats() const
{
	using namespace ::arataga::stats::dns;

	dns_stats_t result{};

	auto collector = lambda_as_enumerator(
			[&result]( const auto & dns_stats ) noexcept {
				result.m_dns_cache_hits += value_of(
						dns_stats.m_dns_cache_hits );

				result.m_dns_successful_lookups += value_of(
						dns_stats.m_dns_successful_lookups );

				result.m_dns_failed_lookups += value_of(
						dns_stats.m_dns_failed_lookups );

				return dns_stats_enumerator_t::go_next;
			} );

	m_app_ctx.m_dns_stats_manager->enumerate( collector );

	return result;
}

void
a_stats_collector_t::format_connection_stats(
	std::ostream & to,
	const connections_stats_t & stats )
{
	using namespace std::string_view_literals;

	using pair_t = std::pair<
			decltype(&connections_stats_t::m_total_connections),
			std::string_view
		>;

	static constexpr std::initializer_list< pair_t > pairs{
		std::pair{
			&connections_stats_t::m_total_connections,
			"TOTAL_CONNECTIONS"sv },
		std::pair{
			&connections_stats_t::m_http_connections,
			"TOTAL_HTTP_PROXY_CONNECTIONS"sv },
		std::pair{
			&connections_stats_t::m_socks5_connections,
			"TOTAL_SOCKS_PROXY_CONNECTIONS"sv },
		std::pair{
			&connections_stats_t::m_remove_reason_normal_completion,
			"REMOVE_REASON_normal_completion"sv },
		std::pair{
			&connections_stats_t::m_remove_reason_io_error,
			"REMOVE_REASON_io_error"sv },
		std::pair{
			&connections_stats_t::m_remove_reason_current_operation_timed_out,
			"REMOVE_REASON_current_operation_timed_out"sv },
		std::pair{
			&connections_stats_t::m_remove_reason_unsupported_protocol,
			"REMOVE_REASON_unsupported_protocol"sv },
		std::pair{
			&connections_stats_t::m_remove_reason_protocol_error,
			"REMOVE_REASON_protocol_error"sv },
		std::pair{
			&connections_stats_t::m_remove_reason_unexpected_error,
			"REMOVE_REASON_unexpected_error"sv },
		std::pair{
			&connections_stats_t::m_remove_reason_no_activity_for_too_long,
			"REMOVE_REASON_no_activity_for_too_long"sv },
		std::pair{
			&connections_stats_t::m_remove_reason_current_operation_canceled,
			"REMOVE_REASON_current_operation_canceled"sv },
		std::pair{
			&connections_stats_t::m_remove_reason_unhandled_exception,
			"REMOVE_REASON_unhandled_exception"sv },
		std::pair{
			&connections_stats_t::m_remove_reason_ip_version_mismatch,
			"REMOVE_REASON_ip_version_mismatch"sv },
		std::pair{
			&connections_stats_t::m_remove_reason_access_denied,
			"REMOVE_REASON_access_denied"sv },
		std::pair{
			&connections_stats_t::m_remove_reason_unresolved_target,
			"REMOVE_REASON_unresolved_target"sv },
		std::pair{
			&connections_stats_t::m_remove_reason_target_end_broken,
			"REMOVE_REASON_target_end_broken"sv },
		std::pair{
			&connections_stats_t::m_remove_reason_user_end_broken,
			"REMOVE_REASON_user_end_broken"sv },
		std::pair{
			&connections_stats_t::m_remove_reason_early_http_response,
			"REMOVE_REASON_early_http_response"sv },
		std::pair{
			&connections_stats_t::m_remove_reason_user_end_closed_by_client,
			"REMOVE_REASON_user_end_closed_by_client"sv },
		std::pair{
			&connections_stats_t::m_remove_reason_http_no_incoming_request,
			"REMOVE_REASON_http_no_incoming_request"sv }
	};

	for( const auto & [v, n] : pairs )
	{
		fmt::print( to, "{}: {}\r\n", n, (stats.*v) );
	}
}

//
// introduce_stats_collector
//
void
introduce_stats_collector(
	so_5::environment_t & env,
	so_5::coop_handle_t parent_coop,
	so_5::disp_binder_shptr_t disp_binder,
	application_context_t app_ctx,
	// There are no initial params at this moment.
	params_t /*params*/ )
{
	auto coop_holder = env.make_coop( parent_coop, std::move(disp_binder) );
	coop_holder->make_agent< a_stats_collector_t >( std::move(app_ctx) );

	env.register_coop( std::move(coop_holder) );
}

} /* namespace arataga::stats_collector */

