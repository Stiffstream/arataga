/*!
 * @file
 * @brief Вспомогательный класс для построчной обработки массива символов.
 */

#pragma once

#include <arataga/utils/line_extractor.hpp>

namespace arataga::utils
{

//
// line_reader_t
//
/*!
 * @brief Вспомогательный класс для построчной обработки массива символов.
 *
 * Принцип использования:
 * - создать экземпляр line_reader_t, в конструктор которого передается
 *   string_view с содержимым обрабатываемого массива символов;
 * - вызвать метод line_reader_t::for_each_line и передать в него
 *   лямбда-функцию, которая будет вызываться для каждой непустой строки
 *   из обрабатываемого массива.
 *
 */
class line_reader_t
{
public:
	class line_t
	{
	private:
		friend class line_reader_t;

		std::string_view m_content;
		line_extractor_t::line_number_t m_number;

		line_t(
			std::string_view content,
			line_extractor_t::line_number_t number )
			:	m_content{ content }
			,	m_number{ number }
		{}

	public:
		[[nodiscard]]
		std::string_view
		content() const noexcept { return m_content; }

		[[nodiscard]]
		auto
		number() const noexcept { return m_number; }
	};

	line_reader_t( std::string_view content )
		:	m_content{ content }
	{}

	// В лямбду будет передаваться единственный аргумент: экземпляр
	// типа line_t, который создается для каждой непустой строки.
	template< typename Handler >
	void
	for_each_line( Handler && handler ) const
	{
		line_extractor_t extractor{ m_content };

		for(;;)
		{
			const auto r = extractor.get_next();
			if( r )
				handler( line_t{ *r, extractor.line_number() } );
			else
				break;
		}
	}

private:
	const std::string_view m_content;
};

} /* namespace arataga::utils */

