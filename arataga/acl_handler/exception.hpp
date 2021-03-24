/*!
 * @file
 * @brief Exception class to be used in implementation of acl_handler.
 */

#pragma once

#include <arataga/exception.hpp>

namespace arataga::acl_handler
{

//
// acl_handler_ex_t
//
//! Type of exception to be used by acl_handler.
struct acl_handler_ex_t : public exception_t
{
public:
	acl_handler_ex_t( const std::string & what )
		:	exception_t{ what }
	{}
};

} /* namespace arataga::acl_handler */

