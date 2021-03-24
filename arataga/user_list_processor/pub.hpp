/*!
 * @file
 * @brief The public interface of user_list_processor-agent.
 */

#pragma once

#include <arataga/application_context.hpp>

#include <arataga/admin_http_entry/pub.hpp>

#include <filesystem>

namespace arataga::user_list_processor
{

//
// params_t
//
/*!
 * @brief Initial parameters for user_list_processor-agent.
 */
struct params_t
{
	//! A path for local copy of user-list file.
	std::filesystem::path m_local_config_path;

	//! mbox for a notification about successful start.
	so_5::mbox_t m_startup_notify_mbox;
};

//
// new_user_list_t
//
/*!
 * @brief A notification about a new incoming user-list.
 */
struct new_user_list_t final : public so_5::message_t
{
	//! An object to send the reply to admin HTTP-entry.
	::arataga::admin_http_entry::replier_shptr_t m_replier;

	//! The content of new incoming user-list.
	const std::string_view m_content;

	new_user_list_t(
		::arataga::admin_http_entry::replier_shptr_t replier,
		std::string_view content )
		:	m_replier{ std::move(replier) }
		,	m_content{ std::move(content) }
	{}
};

//
// introduce_user_list_processor
//
/*!
 * @brief A factory for creation of a new user_list_processor-agent and
 * binding it to the specified dispatcher.
 */
void
introduce_user_list_processor(
	//! SObjectizer Environment to work within.
	so_5::environment_t & env,
	//! The dispatcher for a new user_list_processor-agent.
	so_5::disp_binder_shptr_t disp_binder,
	//! The context of the whole application.
	application_context_t app_ctx,
	//! Initial params for a new user_list_processor-agent.
	params_t params );

} /* namespace arataga::user_list_processor */

