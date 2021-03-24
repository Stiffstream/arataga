/*!
 * @file
 * @brief Stuff for introduction of stats_collector.
 */

#pragma once

#include <arataga/application_context.hpp>

namespace arataga::stats_collector
{

//
// params_t
//
/*!
 * @brief Initial parameters for stats_collector.
 *
 * @note
 * At this point it's an empty struct. But it can be extended later.
 */
struct params_t
{
};

//
// introduce_stats_collector
//
/*!
 * @brief A factory for creation of stats_collector-agent and registration
 * of the new agent with binding to the specified dispatcher.
 */
void
introduce_stats_collector(
	//! SObjectizer Environment to work within.
	so_5::environment_t & env,
	//! The parent coop for a new agent.
	so_5::coop_handle_t parent_coop,
	//! Dispatcher for a new agent.
	so_5::disp_binder_shptr_t disp_binder,
	//! The context of the whole application.
	application_context_t app_ctx,
	//! Initial parameters for a new agent.
	params_t params );

} /* namespace arataga::stats_collector */

