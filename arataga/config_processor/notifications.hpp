/*!
 * @file
 * @brief Notifications to be sent by config_processor agent.
 */

#pragma once

#include <arataga/config.hpp>

#include <so_5/all.hpp>

namespace arataga::config_processor
{

//
// started_t
//
/*!
 * @brief Notification about the successful start.
 */
struct started_t final : public so_5::signal_t {};

//
// updated_dns_params_t
//
/*!
 * @brief Notification about updates for DNS-resolver.
 */
struct updated_dns_params_t final : public so_5::message_t
{
	std::chrono::milliseconds m_cache_cleanup_period;
	std::chrono::milliseconds m_dns_resolving_timeout;

	updated_dns_params_t(
		std::chrono::milliseconds cache_cleanup_period,
		std::chrono::milliseconds dns_resolving_timeout )
		:	m_cache_cleanup_period{ cache_cleanup_period }
		,	m_dns_resolving_timeout{ dns_resolving_timeout }
	{}
};

//
// updated_common_acl_params_t
//
/*!
 * @brief Notification about updates for common parameters for all ACL.
 */
struct updated_common_acl_params_t final : public so_5::message_t
{
	//! New parameters.
	const common_acl_params_t m_params;

	updated_common_acl_params_t(
		const common_acl_params_t & params )
		:	m_params{ params }
	{}
};

//
// updated_auth_params_t
//
/*!
 * @brief Notification about new authentification parameters.
 */
struct updated_auth_params_t final : public so_5::message_t
{
	/*!
	 * @brief Denied TCP-ports.
	 */
	denied_ports_config_t m_denied_ports;

	/*!
	 * @brief A time-out before sending the negative response.
	 */
	std::chrono::milliseconds m_failed_auth_reply_timeout;

	updated_auth_params_t(
		denied_ports_config_t denied_ports,
		std::chrono::milliseconds failed_auth_reply_timeout )
		:	m_denied_ports{ std::move(denied_ports) }
		,	m_failed_auth_reply_timeout{ failed_auth_reply_timeout }
	{}
};

} /* namespace arataga::config_processor */

