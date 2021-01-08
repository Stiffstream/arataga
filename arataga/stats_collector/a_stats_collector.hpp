/*!
 * @file
 * @brief Агент для сбора статистики.
 */

#pragma once

#include <arataga/stats_collector/introduce_stats_collector.hpp>
#include <arataga/stats_collector/msg_get_stats.hpp>

namespace arataga::stats_collector
{

//
// a_stats_collector_t
//
class a_stats_collector_t final : public so_5::agent_t
{
public:
	a_stats_collector_t(
		context_t ctx,
		application_context_t app_ctx );

	void
	so_define_agent() override;

private:
	//! Тип для счетчиков значений.
	using counter_t = std::uint_fast64_t;

	//! Тип для хранения общих значений по подключениям.
	struct connections_stats_t
	{
		counter_t m_total_connections{};
		counter_t m_http_connections{};
		counter_t m_socks5_connections{};
		counter_t m_remove_reason_normal_completion{};
		counter_t m_remove_reason_io_error{};
		counter_t m_remove_reason_current_operation_timed_out{};
		counter_t m_remove_reason_unsupported_protocol{};
		counter_t m_remove_reason_protocol_error{};
		counter_t m_remove_reason_unexpected_error{};
		counter_t m_remove_reason_no_activity_for_too_long{};
		counter_t m_remove_reason_current_operation_canceled{};
		counter_t m_remove_reason_unhandled_exception{};
		counter_t m_remove_reason_ip_version_mismatch{};
		counter_t m_remove_reason_access_denied{};
		counter_t m_remove_reason_unresolved_target{};
		counter_t m_remove_reason_target_end_broken{};
		counter_t m_remove_reason_user_end_broken{};
		counter_t m_remove_reason_early_http_response{};
		counter_t m_remove_reason_user_end_closed_by_client{};
		counter_t m_remove_reason_http_no_incoming_request{};
	};

	//! Тип для хранения общих значений по аутентификациям.
	struct auth_stats_t
	{
		counter_t m_auth_total_count{};
		counter_t m_auth_by_ip_count{};
		counter_t m_failed_auth_by_ip_count{};
		counter_t m_auth_by_login_count{};
		counter_t m_failed_auth_by_login_count{};
		counter_t m_failed_authorization_denied_port{};
	};

	//! Тип для хранения общих значений по DNS-lookup.
	struct dns_stats_t
	{
		counter_t m_dns_cache_hits{};
		counter_t m_dns_successful_lookups{};
		counter_t m_dns_failed_lookups{};
	};

	const application_context_t m_app_ctx;

	void
	on_get_current_stats( mhood_t< get_current_stats_t > cmd );

	[[nodiscard]]
	connections_stats_t
	get_current_connections_stats() const;

	[[nodiscard]]
	auth_stats_t
	get_current_auth_stats() const;

	[[nodiscard]]
	dns_stats_t
	get_current_dns_stats() const;

	static void
	format_connection_stats(
		std::ostream & to,
		const connections_stats_t & stats );
};

} /* namespace arataga::stats_collector */

