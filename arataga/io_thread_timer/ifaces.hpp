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
//FIXME: document this!
class consumer_t
{
protected:
	~consumer_t() = default;

public:
	virtual void
	on_timer() noexcept = 0;
};

//
// provider_t
//
//FIXME: document this!
class provider_t
{
protected:
	~provider_t() = default;

public:
	virtual void
	activate_consumer( consumer_t & consumer ) = 0;

	virtual void
	deactivate_consumer( consumer_t & consumer ) noexcept = 0;
};

} /* namespace arataga::io_thread_timer */

