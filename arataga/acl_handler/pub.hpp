/*!
 * @file
 * @brief The public part of acl_handler-agent.
 */

#pragma once

#include <arataga/utils/acl_req_id.hpp>

#include <arataga/io_thread_timer/ifaces.hpp>

#include <arataga/application_context.hpp>

#include <arataga/config.hpp>

#include <asio/io_context.hpp>

namespace arataga::acl_handler
{

//
// params_t
//
/*!
 * @brief Initial parameters for acl_handler-agent.
 */
struct params_t
{
	//! Asio's io_context to be used by the agent.
	asio::io_context & m_io_ctx;

	//! ACL parameters to be used by the agent.
	acl_config_t m_acl_config;

	//! mbox of dns_resolver to be used.
	so_5::mbox_t m_dns_mbox;

	//! mbox of authentificator to be used.
	so_5::mbox_t m_auth_mbox;

	//! Timer-provider to be used by the agent.
	arataga::io_thread_timer::provider_t & m_timer_provider;

	//! Unique name to be used for logging.
	std::string m_name;

	//! Unique ACL ID seed to be used by this ACL.
	/*!
	 * @since v.0.3.1.2
	 */
	arataga::utils::acl_req_id_seed_t m_acl_id_seed;

	//! Common parameters for all ACLs.
	common_acl_params_t m_common_acl_params;
};

//
// shutdown_t
//
/*!
 * @brief Special signal that tells that acl_handler-agent has to
 * finish its work.
 *
 * When this signal is received acl_handler-agent has to close its
 * entry-point, then it should deregister itself.
 */
struct shutdown_t final : public so_5::signal_t {};

//
// introduce_acl_handler
//
/*!
 * @brief A factory for the creation of a new acl_handler-agent with
 * binding to the specified dispatcher.
 *
 * Returns a mbox for interaction with the new acl_handler-agent.
 */
[[nodiscard]]
so_5::mbox_t
introduce_acl_handler(
	//! SObjectizer Environment to work within.
	so_5::environment_t & env,
	//! The parent for a new agent.
	so_5::coop_handle_t parent_coop,
	//! The dispatcher for a new agent.
	so_5::disp_binder_shptr_t disp_binder,
	//! The context of the whole application.
	application_context_t app_ctx,
	//! Initial parameters for a new agent.
	params_t params );

} /* namespace arataga::acl_handler */

