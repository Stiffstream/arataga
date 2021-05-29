/*!
 * @file
 * @brief Tools for handling periodic timer events on an io-thread.
 */

#pragma once

namespace arataga::io_thread_timer
{

//
// consumer_t
//
/*!
 * @brief Interface of a consumer of timer events.
 *
 * Since v.0.5 a new scheme of handling one-second-timer is used.
 * There is a single one_second_timer_t subscriber for every io-thread.
 * That subscriber is called 'timer_provider'. The timer_provider holds
 * a list of active entities that want to receive timer event. Those
 * entities are called 'timer_consumers'.
 *
 * When timer_provider receives one_second_timer_t event it calls
 * every active timer_consumer.
 *
 * This class describes an interface of a timer_consumer.
 */
class consumer_t
{
	friend class provider_t;

	bool m_activated{ false };
	consumer_t * m_prev{};
	consumer_t * m_next{};

protected:
	// NOTE: the destructor is not virtual and isn't public.
	// This interface is not intended to be used for handling
	// object lifetime.
	~consumer_t() = default;

public:
	consumer_t() = default;

	virtual void
	on_timer() noexcept = 0;
};

//
// provider_t
//
/*!
 * @brief Interface of timer_provider that receives one_second_timer events.
 *
 * See consumer_t for more details about timer-handling scheme since v.0.5.
 */
class provider_t
{
	class dummy_consumer_t final : public consumer_t
	{
	public:
		void
		on_timer() noexcept override { /* Nothing to do. */ }
	};

protected:
	// NOTE: the destructor is not virtual and isn't public.
	// This interface is not intended to be used for handling
	// object lifetime.
	~provider_t() = default;

	dummy_consumer_t m_head;
	dummy_consumer_t m_tail;
	
	void
	inform_every_consumer() noexcept
	{
		consumer_t * current = &m_head;
		while( current )
		{
			auto * next = current->m_next;
			current->on_timer();

			current = next;
		}
	}

public:
	provider_t() noexcept
	{
		m_head.m_next = &m_tail;
		m_tail.m_prev = &m_head;
	}

	void
	activate_consumer( consumer_t & consumer ) noexcept
	{
		if( !consumer.m_activated )
		{
			consumer.m_activated = true;
			auto * old_last = m_tail.m_prev;
			old_last->m_next = m_tail.m_prev = &consumer;
			consumer.m_prev = old_last;
			consumer.m_next = &m_tail;
		}
	}

	void
	deactivate_consumer( consumer_t & consumer ) noexcept
	{
		if( consumer.m_activated )
		{
			consumer.m_next->m_prev = consumer.m_prev;
			consumer.m_prev->m_next = consumer.m_next;

			consumer.m_next = nullptr;
			consumer.m_prev = nullptr;

			consumer.m_activated = false;
		}
	}
};

} /* namespace arataga::io_thread_timer */

