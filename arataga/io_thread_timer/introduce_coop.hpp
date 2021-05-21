/*!
 * @file
 * @brief Factory for the creation of a coop with timer_provider.
 */

#pragma once

#include <arataga/io_thread_timer/ifaces.hpp>

#include <arataga/application_context.hpp>

#include <tuple>

namespace arataga::io_thread_timer
{

//
// introduce_coop
//
/*!
 * @brief Factory for create a new coop with timer_provider inside.
 */
[[nodiscard]]
std::tuple<so_5::coop_handle_t, provider_t*>
introduce_coop(
	//! SObjectizer Environment to work in.
	so_5::environment_t & env,
	//! Parent coop for the new cooperation with timer_provider.
	so_5::coop_handle_t parent_coop,
	//! Dispatcher to be used for agent(s) in the new coop.
	so_5::disp_binder_shptr_t disp_binder,
	//! Context of the whole application.
	application_context_t app_ctx );

} /* namespace arataga::io_thread_timer */

