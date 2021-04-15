/*!
 * @file
 * @brief Public part of config_processor agent.
 */

#pragma once

#include <arataga/application_context.hpp>

#include <arataga/admin_http_entry/pub.hpp>

#include <arataga/io_threads_count.hpp>

#include <filesystem>

namespace arataga::config_processor
{

//
// params_t
//
/*!
 * @brief Initial parameters for the agent.
 */
struct params_t
{
	//! Path where local config copies should be stored.
	std::filesystem::path m_local_config_path;

	//! mbox for acknoledgement of successful start.
	so_5::mbox_t m_startup_notify_mbox;

	//! Number of io_threads to be created.
	io_threads_count_t m_io_threads_count{ io_threads_count::default_t{} };
};

//
// new_config_t
//
/*!
 * @brief Message about new config.
 */
struct new_config_t final : public so_5::message_t
{
	//! Replier for the incoming request.
	::arataga::admin_http_entry::replier_shptr_t m_replier;

	//! The content of the new config.
	const std::string_view m_content;

	new_config_t(
		::arataga::admin_http_entry::replier_shptr_t replier,
		std::string_view content )
		:	m_replier{ std::move(replier) }
		,	m_content{ std::move(content) }
	{}
};

//
// get_acl_list_t
//
/*!
 * @brief Message with a request of retrieving of the current ACL list.
 */
struct get_acl_list_t final : public so_5::message_t
{
	//! Replier for the incoming request.
	::arataga::admin_http_entry::replier_shptr_t m_replier;

	get_acl_list_t(
		::arataga::admin_http_entry::replier_shptr_t replier )
		:	m_replier{ std::move(replier) }
	{}
};

//
// debug_auth
//
/*!
 * @brief Message with a request for test authentification.
 */
struct debug_auth_t final : public so_5::message_t
{
	//! Replier for the incoming request.
	::arataga::admin_http_entry::replier_shptr_t m_replier;

	//! Authentification parameters.
	::arataga::admin_http_entry::debug_requests::authentificate_t m_request;

	debug_auth_t(
		::arataga::admin_http_entry::replier_shptr_t replier,
		::arataga::admin_http_entry::debug_requests::authentificate_t
				request )
		:	m_replier{ std::move(replier) }
		,	m_request{ std::move(request) }
	{}
};

//
// debug_dns_resolve_t
//
/*!
 * @brief Message with a request for test domain name resolution.
 */
struct debug_dns_resolve_t final : public so_5::message_t
{
	//! Replier for the incoming request.
	::arataga::admin_http_entry::replier_shptr_t m_replier;

	//! Parameters for domain name resolution.
	::arataga::admin_http_entry::debug_requests::dns_resolve_t m_request;

	debug_dns_resolve_t(
		::arataga::admin_http_entry::replier_shptr_t replier,
		::arataga::admin_http_entry::debug_requests::dns_resolve_t
				request )
		:	m_replier{ std::move(replier) }
		,	m_request{ std::move(request) }
	{}
};

//
// introduce_config_processor
//
/*!
 * @brief Function for create and launch config_processor agent
 * in the specified SObjectizer Environment.
 */
void
introduce_config_processor(
	//! SObjectizer Environment for a new agent.
	so_5::environment_t & env,
	//! The dispatcher for a new agent.
	so_5::disp_binder_shptr_t disp_binder,
	//! The context of the whole aragata app.
	application_context_t app_ctx,
	//! Initial parameters for a new agent.
	params_t params );

} /* namespace arataga::config_processor */

