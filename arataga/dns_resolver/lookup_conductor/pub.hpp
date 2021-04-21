/*!
 * @file
 * @brief The public part of lookup_conductor-agent's interface.
 */

#pragma once

#include <arataga/application_context.hpp>

#include <so_5/all.hpp>

namespace arataga::dns_resolver::lookup_conductor
{

//
// add_lookup_conductors_to_coop
//
/*!
 * @brief A factory for the creation of lookup_conductor-agents with
 * the binding to the specified dispatcher.
 */
void
add_lookup_conductors_to_coop(
	//! The target coop.
	so_5::coop_t & coop,
	//! The context of the whole application.
	application_context_t app_ctx,
	//! Unique prefix for agents names.
	const std::string & name_prefix,
	//! Mbox to be used for subscription to incoming requests.
	const so_5::mbox_t & incoming_requests_mbox,
	//! Mbox for outgoing requests to nameserver_interactor.
	const so_5::mbox_t & nameserver_interactor_mbox );

} /* namespace arataga::dns_resolver::lookup_conductor */

