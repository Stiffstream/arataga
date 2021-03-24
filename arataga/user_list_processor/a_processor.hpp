/*!
 * @file
 * @brief Agent for handling user-list.
 */

#pragma once

#include <arataga/user_list_processor/pub.hpp>

#include <arataga/config.hpp>
#include <arataga/user_list_auth_data.hpp>

namespace arataga::user_list_processor
{

//
// a_processor_t
//
/*!
 * @brief Agent for handling user-list.
 */
class a_processor_t : public so_5::agent_t
{
public:
	//! Initializing constructor.
	a_processor_t(
		//! SObjectizer-related parameters.
		context_t ctx,
		//! The context of the whole application.
		application_context_t app_ctx,
		//! Initial parameters for the agent.
		params_t params );

	void
	so_define_agent() override;

	void
	so_evt_start() override;

private:
	//! The context of the whole application.
	const application_context_t m_app_ctx;

	//! Initial parameters for the agent.
	const params_t m_params;

	//! Name of the file with local copy of user-list.
	const std::filesystem::path m_local_user_list_file_name;

	//! Handler for a new incoming user-list.
	void
	on_new_user_list(
		mhood_t< new_user_list_t > cmd );

	//! Attempt to load user-list from the local copy at the start of agent.
	void
	try_load_local_user_list_first_time();

	//! Attempt to handle a new incoming user-list.
	void
	try_handle_new_user_list_from_post_request(
		std::string_view content );

	//! Attempt to load user-list from the local copy.
	/*!
	 * Handles exceptions thrown during loading of file content.
	 *
	 * If there is an error then empty value is returned.
	 */
	std::optional< ::arataga::user_list_auth::auth_data_t >
	try_load_local_user_list_content();

	//! Distribution of a new user-list to subscribers of that notification.
	/*!
	 * This method is marked as noexcept because it intercepts all
	 * exceptions, logs them, and terminates the application.
	 * This logic is implemented because unability to spread a new
	 * user-list is a fatal error that can't be recovered.
	 */
	void
	distribute_updated_user_list(
		::arataga::user_list_auth::auth_data_t auth_data ) noexcept;

	//! Storing of a new user-list to local file.
	/*!
	 * @note
	 * Exceptions are caught, logged and suppressed.
	 */
	void
	store_new_user_list_to_file(
		std::string_view content );
};

} /* namespace arataga::user_list_processor */

