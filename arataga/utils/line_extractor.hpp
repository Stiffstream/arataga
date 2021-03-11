/*!
 * @file
 * @brief A tool for spliting a vector of chars into lines.
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
 * @brief A helper class for line-by-line extraction of the content
 * of previously loaded file.
 *
 * This class counts line numbers and skips lines with comments.
 *
 * All empty lines are ignored.
 *
 * All leading spaces in extracted lines are removed.
 */
class line_extractor_t
{
public:
	//! Type for holding line numbers.
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
		// Remove the comment.
		// We have to skip all symbols till the end-of-line.
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
				// That is the case of \r\n, two symbols have to be removed.
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

		// We have to take all contnent except the end-of-line.
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
			// Skip leading spaces if any.
			const auto non_space_pos = m_content.find_first_not_of( spaces() );
			if( std::string_view::npos != non_space_pos )
			{
				// Remove leading spaces.
				m_content = m_content.substr( non_space_pos );

				// m_content is not empty at that point,
				// so it's safe to access the first char.
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
				// There are only space symbols.
				m_content.remove_prefix( m_content.size() );
			}
		}

		// We are here in two cases only:
		// - the next line extracted;
		// - the end-of-file reached.
		return result;
	}
};

} /* namespace arataga::utils */

