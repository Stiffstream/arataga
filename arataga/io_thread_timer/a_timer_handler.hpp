/*!
 * @file
 * @brief Agent for handling one_second_timer events.
 */

#pragma once

#include <arataga/io_thread_timer/ifaces.hpp>

#include <arataga/application_context.hpp>
#include <arataga/one_second_timer.hpp>

namespace arataga::io_thread_timer
{

//
// a_timer_handler_t
//
/*!
 * @brief Agent for handling one_second_timer events for an io-thread.
 *
 * This agent implements provider_t interface. It holds a set of active
 * consumers and calls consumer_t::on_timer() method for every active
 * consumer when one_second_timer_t signal arrives.
 */
class a_timer_handler_t
	:	public so_5::agent_t
	,	public provider_t
{
public:
	a_timer_handler_t(
		context_t ctx,
		application_context_t app_ctx );
	~a_timer_handler_t() = default;

	void
	so_define_agent() override;

private:
	//! Context of the whole application.
	const application_context_t m_app_ctx;

	void
	on_one_second_timer( mhood_t<one_second_timer_t> );
};

} /* namespace arataga::io_thread_timer */

