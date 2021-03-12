/*!
 * @file
 * @brief Agent that starts all main agents in the right sequence.
 */

#pragma once

#include <arataga/startup_manager/pub.hpp>

#include <arataga/user_list_processor/notifications.hpp>
#include <arataga/config_processor/notifications.hpp>

#include <arataga/admin_http_entry/pub.hpp>

#include <so_5/all.hpp>

#include <filesystem>

namespace arataga::startup_manager
{

//
// a_manager_t
//
/*!
 * @brief Agent that starts all main agents in the right sequence.
 *
 * This agent creates an instance of application_context that will
 * be used by all other agents in the application.
 *
 * The sequence of launching the main agents:
 * - user_list_processor;
 * - config_processor.
 */
class a_manager_t : public so_5::agent_t
{
public:
	//! Initializing constructor.
	a_manager_t(
		//! SObjectizer-related parameters for the agent.
		context_t ctx,
		//! Initial params for the agent.
		params_t params );

	void
	so_define_agent() override;

	void
	so_evt_start() override;

	void
	so_evt_finish() override;

private:
	//! Notification about too long time of user_list_processor's startup.
	struct user_list_processor_startup_timeout final : public so_5::signal_t {};

	//! Notification about too long time of config_processor's startup.
	struct config_processor_startup_timeout final : public so_5::signal_t {};

	//! Command for the creation of admin HTTP-entry.
	struct make_admin_http_entry final : public so_5::signal_t {};

	//! Initial parameters for the agent.
	const params_t m_params;

	//! The context of the whole application.
	const application_context_t m_app_ctx;

	//! State for waiting start of user_list_processor agent.
	state_t st_wait_user_list_processor{ this, "wait_user_list_processor" };
	//! State for waiting start of wait_config_processor.
	state_t st_wait_config_processor{ this, "wait_config_processor" };
	//! State for launching admin HTTP-entry.
	state_t st_http_entry_stage{ this, "http_entry_stage" };
	//! The normal state when all components are started.
	state_t st_normal{ this, "normal" };

	//! Global one-second timer.
	so_5::timer_id_t m_one_second_timer;

	//! The implementation of gateway for interaction with
	//! admin HTTP-entry.
	std::unique_ptr< ::arataga::admin_http_entry::requests_mailbox_t >
			m_admin_entry_requests_mailbox;

	//! The admin HTTP-entry.
	::arataga::admin_http_entry::running_entry_handle_t m_admin_entry;

	//! Create an instance of application_context for the whole application.
	[[nodiscard]]
	static application_context_t
	make_application_context(
		so_5::environment_t & env,
		const params_t & params );

	//! on_enter-handler for wait_user_list_processor state.
	/*!
	 * Creates a user_list_processor agent.
	 */
	void
	on_enter_wait_user_list_processor();

	//! Handler of the start of user_list_processor agent.
	void
	on_user_list_processor_started(
		mhood_t< arataga::user_list_processor::started_t > );

	//! Handler for the timeout of user_list_processor startup.
	[[noreturn]] void
	on_user_list_processor_startup_timeout(
		mhood_t< user_list_processor_startup_timeout > );

	//! on_enter-handler for wait_config_processor state.
	/*!
	 * Creates a config_processor agent.
	 */
	void
	on_enter_wait_config_processor();

	//! Handler for the start of config_processor agent.
	void
	on_config_processor_started(
		mhood_t< arataga::config_processor::started_t > );

	//! Handler for the timeout of config_processor startup.
	[[noreturn]] void
	on_config_processor_startup_timeout(
		mhood_t< config_processor_startup_timeout > );

	//! on_enter-handler for http_entry_stage state.
	/*!
	 * The agent sends make_admin_http_entry to itself.
	 *
	 * We can't do actions that throws in on_enter-handler because
	 * on_enter-handler should be noexcept method. So we send a message
	 * and then do all necessary actions in an ordinary event-handler
	 * where exceptions can go out.
	 */
	void
	on_enter_http_entry_stage();

	//! Handler for a command to create admin HTTP-entry.
	void
	on_make_admin_http_entry(
		mhood_t< make_admin_http_entry > );
};

} /* namespace arataga::startup_manager */

