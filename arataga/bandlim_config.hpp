/*!
 * @file
 * @brief Параметры ограничения пропускной способности.
 */

#pragma once

#include <cstdint>
#include <iostream>

namespace arataga
{

//
// bandlim_config_t
//
/*!
 * @brief Ограничения на пропускную способность для клиента.
 */
struct bandlim_config_t
{
	//! Тип для хранения одного значения.
	using value_t = std::uint_fast64_t;

	//! Специальное значение, которое указывает, что лимит не задан.
	static constexpr value_t unlimited{ 0u };

	//! Ограничение на поток трафика от целевого хоста к клиенту.
	/*!
	 * Для клиента это входящий трафик.
	 *
	 * Задается в байтах.
	 */
	value_t m_in{ unlimited };

	//! Ограничение на поток трафика от клиента к целевому хосту.
	/*!
	 * Для клиента это входящий трафик.
	 *
	 * Задается в байтах.
	 */
	value_t m_out{ unlimited };

	//! Вспомогательный метод для определения того, что лимит не задан.
	/*!
	 * Пример использования:
	 * @code
	 * if( bandlim_config_t::is_unlimited(my_limits.m_in) ) {...}
	 * @endcode
	 */
	[[nodiscard]]
	static bool
	is_unlimited( value_t v ) noexcept { return unlimited == v; }
};

inline std::ostream &
operator<<( std::ostream & to, const bandlim_config_t & v )
{
	to << "in=";
	if( bandlim_config_t::is_unlimited( v.m_in ) )
		to << "unlimited";
	else
		to << v.m_in;

	to << ", out=";
	if( bandlim_config_t::is_unlimited( v.m_out ) )
		to << "unlimited";
	else
		to << v.m_out;

	return to;
}

} /* namespace arataga */

