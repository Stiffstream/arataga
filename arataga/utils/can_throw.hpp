/*!
 * @file
 * @brief Stuff related to can_throw_t class.
 */

#pragma once

namespace arataga::utils
{

//
// can_throw_t
//
class can_throw_t
{
	friend class exception_handling_context_t;

	can_throw_t() noexcept = default;

public:
	~can_throw_t() noexcept = default;

	can_throw_t( const can_throw_t & ) noexcept = default;
	can_throw_t( can_throw_t && ) noexcept = default;

	can_throw_t &
	operator=( const can_throw_t & ) noexcept = default;
	can_throw_t &
	operator=( can_throw_t && ) noexcept = default;
};

//
// exception_handling_context_t
//
/*!
 * @brief The only class that can create instances of can_throw.
 */
class exception_handling_context_t
{
public:
	can_throw_t
	make_can_throw_marker() const noexcept { return {}; }
};

} /* namespace arataga::utils */

