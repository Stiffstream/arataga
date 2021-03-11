/*!
 * @file
 * @brief A helper class for line-by-line processing of a char array.
 */

#pragma once

#include <arataga/utils/line_extractor.hpp>

namespace arataga::utils
{

//
// line_reader_t
//
/*!
 * @brief A helper class for line-by-line processing of a char array.
 *
 * The main scenario of the usage:
 * - create an instance of line_reader_t. Pass a string_view with a
 *   content of char array to the constructor;
 * - call line_reader_t::for_each_line method and pass a lambda function
 *   to it. This lambda will be called for every non-empty line
 *   from the char array.
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

	// A single argument will be passed to lambda-function: an instance
	// of line_t object that will be created for every non-empty line.
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

