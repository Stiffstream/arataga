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
protected:
	// NOTE: the destructor is not virtual and isn't public.
	// This interface is not intended to be used for handling
	// object lifetime.
	~consumer_t() = default;

public:
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
protected:
	// NOTE: the destructor is not virtual and isn't public.
	// This interface is not intended to be used for handling
	// object lifetime.
	~provider_t() = default;

public:
	// NOTE: this method is not noexcept, it can throw.
	virtual void
	activate_consumer( consumer_t & consumer ) = 0;

	virtual void
	deactivate_consumer( consumer_t & consumer ) noexcept = 0;
};

} /* namespace arataga::io_thread_timer */

