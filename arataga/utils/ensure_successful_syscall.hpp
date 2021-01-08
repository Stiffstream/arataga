/*!
 * @file
 * @brief Вспомогательная функция для выброса исключения, если
 * системный вызов вернул ошибку.
 */

#pragma once

#include <system_error>
#include <stdexcept>

namespace arataga::utils
{

inline void
ensure_successful_syscall(int ret_code, const std::string & what)
{
	if(-1 == ret_code)
	{
		throw std::runtime_error( what + ": failed -> " +
				std::system_category().message(errno));
	}
}

inline void
ensure_successful_syscall(int ret_code, const char * what)
{
	if(-1 == ret_code)
	{
		throw std::runtime_error( std::string(what) + ": failed -> " +
				std::system_category().message(errno));
	}
}

} /* namespace arataga::utils */

