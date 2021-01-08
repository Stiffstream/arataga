/*!
 * @file
 * @brief Класс исключения, который используется в реализации acl_handler.
 */

#pragma once

#include <arataga/exception.hpp>

namespace arataga::acl_handler
{

//
// acl_handler_ex_t
//
//! Тип исключения, которое может выбрасывать acl_handler.
struct acl_handler_ex_t : public exception_t
{
public:
	acl_handler_ex_t( const std::string & what )
		:	exception_t{ what }
	{}
};

} /* namespace arataga::acl_handler */

