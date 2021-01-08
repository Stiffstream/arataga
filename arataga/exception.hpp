/*!
 * @file
 * @brief Базовый класс для исключений.
 */

#pragma once

#include <stdexcept>

namespace arataga
{

/*!
 * @brief Базовый класс для всех исключений, которые будут порождаться
 * кодом самого arataga.
 */
class exception_t : public std::runtime_error
{
public:
	// Наследуем конструкторы из базового класса.
	using std::runtime_error::runtime_error;
};

} /* namespace arataga */

