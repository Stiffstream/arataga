/*!
 * @file
 * @brief Agent for handling one_second_timer events.
 */

#include <arataga/io_thread_timer/a_timer_handler.hpp>

#include <arataga/nothrow_block/macros.hpp>

namespace arataga::io_thread_timer
{

//
// a_timer_handler_t
//
a_timer_handler_t::a_timer_handler_t(
	context_t ctx,
	application_context_t app_ctx )
	:	so_5::agent_t{ std::move(ctx) }
	,	m_app_ctx{ std::move(app_ctx) }
{}

void
a_timer_handler_t::so_define_agent()
{
	so_subscribe( m_app_ctx.m_global_timer_mbox )
		.event( &a_timer_handler_t::on_one_second_timer );
}

void
a_timer_handler_t::activate_consumer( consumer_t & consumer )
{
	m_active_consumers.insert( &consumer );
}

void
a_timer_handler_t::deactivate_consumer( consumer_t & consumer ) noexcept
{
	// std::set's erase is not declared as noexcept, so intercept and
	// ignore all exceptions.
	ARATAGA_NOTHROW_BLOCK_BEGIN()
		ARATAGA_NOTHROW_BLOCK_STAGE(deactivate_consumer)

		m_active_consumers.erase( &consumer );
	ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_IGNORE)
}

void
a_timer_handler_t::on_one_second_timer( mhood_t<one_second_timer_t> )
{
	// It is possible that consumer will be deactivated just inside
	// `on_timer` call. So we should take care about it.
	for( auto it = m_active_consumers.begin();
			it != m_active_consumers.end();
			/* nothing to do! */ )
	{
		auto * consumer = *it;
		++it;

		consumer->on_timer();
	}
}

[[nodiscard]]
std::tuple<so_5::coop_handle_t, provider_t*>
introduce_coop(
	so_5::environment_t & env,
	so_5::coop_handle_t parent_coop,
	so_5::disp_binder_shptr_t disp_binder,
	application_context_t app_ctx )
{
	auto coop_holder = env.make_coop( parent_coop, std::move(disp_binder) );
	provider_t * provider{
		coop_holder->make_agent< a_timer_handler_t >( std::move(app_ctx) )
	};

	auto coop_handle = env.register_coop( std::move(coop_holder) );

	return { std::move(coop_handle), provider };
}

} /* namespace arataga::io_thread_timer */

