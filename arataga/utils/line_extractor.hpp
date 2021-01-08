/*!
 * @file
 * @brief Инструмент для дробления массива символов на строки.
 */

#pragma once

#include <cstdint>
#include <string_view>

namespace arataga::utils
{

//
// line_extractor_t
//
/*!
 * @brief Вспомогательный класс для построчного извлечения содержимого
 * из ранее загруженного в память содержимого файла.
 *
 * При извлечении строк подсчитываются номера строк, а так же
 * выбрасываются строки с комментариями.
 *
 * Игнорируются пустые строки.
 *
 * Лидирующие пробелы в извлекаемых строках удаляются.
 */
class line_extractor_t
{
public:
	//! Тип для хранения номеров строк.
	using line_number_t = std::uint_fast32_t;

private:
	[[nodiscard]]
	static constexpr std::string_view
	crlf() noexcept { return { "\r\n" }; }

	[[nodiscard]]
	static constexpr std::string_view
	spaces() noexcept { return { " \t\x0b" }; }

	std::string_view m_content;

	line_number_t m_line_number{ 1u };

	void
	handle_comment() noexcept
	{
		// Избавляемся от содержимого комментария.
		// Нужно пропустить все символы до конца строки.
		m_content.remove_prefix(
				std::min( m_content.find_first_of( crlf() ), m_content.size() ) );
	}

	void
	handle_eol( char front_ch ) noexcept
	{
		++m_line_number;
		std::string_view::size_type chars_to_remove{ 1u };

		if( '\r' == front_ch || m_content.length() >= 2u )
		{
			if( '\n' == m_content[ 1u ] )
			{
				// Это случай \r\n. Изымать нужно сразу два символа.
				chars_to_remove = 2u;
			}
		}

		m_content.remove_prefix( chars_to_remove );
	}

	[[nodiscard]]
	std::string_view
	handle_non_comment() noexcept
	{
		std::string_view result;

		// Нужно взять все, что идет до конца строки.
		const auto chars_to_extract = std::min(
				m_content.find_first_of( crlf() ),
				m_content.size() );

		result = m_content.substr( 0u, chars_to_extract );
		m_content.remove_prefix( chars_to_extract );

		return result;
	}

public:
	line_extractor_t( std::string_view content ) noexcept
		:	m_content{ content }
	{}

	[[nodiscard]]
	auto
	line_number() const noexcept { return m_line_number; }

	[[nodiscard]]
	std::optional< std::string_view >
	get_next() noexcept
	{
		std::optional< std::string_view > result{ std::nullopt };

		while( !result && !m_content.empty() )
		{
			// Пропускаем лидирующие пробелы, если они есть.
			const auto non_space_pos = m_content.find_first_not_of( spaces() );
			if( std::string_view::npos != non_space_pos )
			{
				// Избавляемся от лидирующих пробелов.
				m_content = m_content.substr( non_space_pos );

				// m_content не может быть пустым в этой точке.
				// Поэтому можно смело обращаться к первому символу.
				const auto front_ch = m_content.front();
				if( '#' == front_ch )
				{
					handle_comment();
				}
				else if( '\r' == front_ch || '\n' == front_ch )
				{
					handle_eol( front_ch );
				}
				else
				{
					result = handle_non_comment();
				}
			}
			else
			{
				// Во входном потоке остались только пробельные символы.
				m_content.remove_prefix( m_content.size() );
			}
		}

		// Если оказались здесь, значит либо получено очередное значение,
		// либо достигли конца входного потока.
		return result;
	}
};

} /* namespace arataga::utils */

