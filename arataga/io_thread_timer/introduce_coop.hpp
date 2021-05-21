/*!
 * @file
 * @brief Factory for the creation of a coop with timer_handler.
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
//FIXME: document this!
[[nodiscard]]
std::tuple<so_5::coop_handle_t, provider_t*>
introduce_coop(
	so_5::environment_t & env,
	so_5::coop_handle_t parent_coop,
	so_5::disp_binder_shptr_t disp_binder,
	application_context_t app_ctx );

} /* namespace arataga::io_thread_timer */

