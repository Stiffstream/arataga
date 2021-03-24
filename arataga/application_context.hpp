/*!
 * @file
 * @brief Definition of context in that arataga's entities will work.
 */

#pragma once

#include <so_5/all.hpp>

#include <arataga/stats/auth/pub.hpp>
#include <arataga/stats/connections/pub.hpp>
#include <arataga/stats/dns/pub.hpp>

namespace arataga
{

//
// application_context_t
//
/*!
 * @brief A struct for holding info necessary for interaction
 * between arataga's entities.
 */
struct application_context_t
{
	//! mbox for interaction with config_processor.
	so_5::mbox_t m_config_processor_mbox;

	//! mbox for interaction with user_list_processor.
	so_5::mbox_t m_user_list_processor_mbox;
	
	//! mbox for spreading info about changes in the configuration.
	so_5::mbox_t m_config_updates_mbox;

	//! mbox for collecting the stats.
	so_5::mbox_t m_stats_collector_mbox;

	//! mbox for messages from the global timer.
	so_5::mbox_t m_global_timer_mbox;

	//! The storage for statistics from ACL.
	std::shared_ptr<
			stats::connections::acl_stats_reference_manager_t > m_acl_stats_manager;

	//! The storage for statistics from authentification operations.
	std::shared_ptr<
			stats::auth::auth_stats_reference_manager_t > m_auth_stats_manager;

	//! The storage for statistics from DNS operations.
	std::shared_ptr<
			stats::dns::dns_stats_reference_manager_t > m_dns_stats_manager;
};

} /* namespace arataga */

