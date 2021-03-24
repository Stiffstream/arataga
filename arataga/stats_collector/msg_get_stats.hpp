/*!
 * @file
 * @brief Messages for stats_collector-agent for retrieving the current stats.
 */
#pragma once

#include <arataga/admin_http_entry/pub.hpp>

#include <so_5/all.hpp>

namespace arataga::stats_collector
{

//
// get_current_stats_t
//
struct get_current_stats_t final : public so_5::message_t
{
	::arataga::admin_http_entry::replier_shptr_t m_replier;

	get_current_stats_t(
		::arataga::admin_http_entry::replier_shptr_t replier )
		:	m_replier{ replier }
	{}
};

} /* namespace arataga::stats_collector */

