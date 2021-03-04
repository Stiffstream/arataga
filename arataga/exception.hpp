/*!
 * @file
 * @brief The base class for exceptions.
 */

#pragma once

#include <stdexcept>

namespace arataga
{

/*!
 * @brief The base class for all exceptions thrown by arataga's code.
 */
class exception_t : public std::runtime_error
{
public:
	// Inherit constructors from the base class.
	using std::runtime_error::runtime_error;
};

} /* namespace arataga */

