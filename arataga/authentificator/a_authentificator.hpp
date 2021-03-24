/*!
 * @file
 * @brief Authentificator agent.
 */

#pragma once

#include <arataga/authentificator/pub.hpp>

#include <arataga/user_list_processor/notifications.hpp>
#include <arataga/config_processor/notifications.hpp>

namespace arataga::authentificator
{

//
// a_authentificator_t
//
/*!
 * @brief Agent that performs authentification and authorization
 * of clients.
 *
 * @attention
 * The subscription to config updates is made in so_evt_start(), not
 * in so_define_agent() as usual. It's because in so_define_agent()
 * agent isn't yet bind to an event-queue and stored in retained
 * mbox messages would be lost. It subscription is made in
 * so_evt_start() then message from retained mbox will be stored
 * in agent's event queue.
 */
class a_authentificator_t final : public so_5::agent_t
{
public:
	//! Initializing constructor.
	a_authentificator_t(
		context_t ctx,
		application_context_t app_ctx,
		params_t params );

	void
	so_define_agent() override;

	void
	so_evt_start() override;

private:
	//! The context of the whole application.
	const application_context_t m_app_ctx;

	//! Initial params for the agent.
	const params_t m_params;

	//! Local stats for the agent.
	::arataga::stats::auth::auth_stats_t m_auth_stats;
	::arataga::stats::auth::auto_reg_t m_auth_stats_reg;

	//! Local copy of user-list.
	/*!
	 * The copy is used for the simplicity of the very first
	 * version of arataga.
	 */
	::arataga::user_list_auth::auth_data_t m_auth_data;

	//! Local copy of denied-ports list.
	denied_ports_config_t m_denied_ports;

	//! The size of time-out before sending a negative response.
	std::chrono::milliseconds m_failed_auth_reply_timeout{ 750 };

	//! Handler for updates of user-list.
	void
	on_updated_user_list(
		mhood_t< ::arataga::user_list_processor::updated_user_list_t > cmd );

	//! Handler for updates of authentification params.
	void
	on_updated_auth_params(
		mhood_t< ::arataga::config_processor::updated_auth_params_t > cmd );

	//! Handler for authentification request.
	void
	on_auth_request(
		mhood_t< auth_request_t > cmd );

	//! Authentification by client's IP-address.
	void
	do_auth_by_ip(
		const auth_request_t & req );

	//! Authentification by client's login/password.
	void
	do_auth_by_login_password(
		const auth_request_t & req );

	//! Completion of the failed authentification attempt.
	void
	complete_failed_auth(
		const auth_request_t & req,
		failure_reason_t reason );

	//! Completion of the successful authentification attempt.
	void
	complete_successful_auth(
		const auth_request_t & req,
		const ::arataga::user_list_auth::user_data_t & user_data );

	//! An attempt to authorize an authentificated client.
	/*!
	 * Return empty value if the client is authorized.
	 */
	[[nodiscard]]
	std::optional< failure_reason_t >
	try_authorize_user(
		const auth_request_t & req );

	//! An attempt to find an individual limit for target domain.
	[[nodiscard]]
	std::optional< one_domain_limit_t >
	try_detect_domain_limits(
		const ::arataga::user_list_auth::user_data_t & user_data,
		const std::string & target_host ) const;
};

} /* namespace arataga::authentificator */

