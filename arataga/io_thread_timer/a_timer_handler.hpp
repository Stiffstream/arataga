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
//FIXME: document this!
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

	void
	activate_consumer( consumer_t & consumer ) override;

	void
	deactivate_consumer( consumer_t & consumer ) noexcept override;

private:
	//! Type of the set of active consumers.
	using consumers_set_t = std::set< consumer_t * >;

	//! Context of the whole application.
	const application_context_t m_app_ctx;

	//! Active consumers.
	consumers_set_t m_active_consumers;

	void
	on_one_second_timer( mhood_t<one_second_timer_t> );
};

} /* namespace arataga::io_thread_timer */

