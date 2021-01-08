/*!
 * @file
 * @brief Класс для представления кусочков предназначенных для отсылки данных.
 */

#pragma once

#include <arataga/acl_handler/buffers.hpp>

#include <arataga/utils/overloaded.hpp>

namespace arataga::acl_handler
{

/*!
 * @brief Класс для представления одного кусочка данных для отсылки в сокет.
 *
 * Кусочек данных может быть представлен либо объектом std::string или
 * fmt::memory_buffer (и тогда его значение нужно забирать к себе, во внутрь
 * out_data_piece_t), либо объектом std::string_view (тогда сами данные никуда
 * копировать не нужно).
 *
 * Класс out_data_piece_t может выступать в качестве buffer-а, по аналогии
 * с классами out_string_view_buffer_t, out_string_buffer_t.
 */
class out_data_piece_t
{
	using piece_holder_t = std::variant<
			out_string_view_buffer_t,
			out_string_buffer_t,
			out_fmt_memory_buffer_t
		>;

	piece_holder_t m_piece;

public:
	out_data_piece_t( std::string_view data )
		:	m_piece{ out_string_view_buffer_t{ data } }
	{}

	out_data_piece_t( std::string data )
		:	m_piece{ out_string_buffer_t{ std::move(data) } }
	{}

	out_data_piece_t( fmt::memory_buffer data )
		:	m_piece{ out_fmt_memory_buffer_t{ std::move(data) } }
	{}

	[[nodiscard]]
	std::size_t
	remaining() const noexcept
	{
		return std::visit( ::arataga::utils::overloaded{
				[]( const out_string_view_buffer_t & b ) {
					return b.remaining();
				},
				[]( const out_string_buffer_t & b ) {
					return b.remaining();
				},
				[]( const out_fmt_memory_buffer_t & b ) {
					return b.remaining();
				}
			},
			m_piece );
	}

	void
	increment_bytes_written( std::size_t bytes ) noexcept
	{
		std::visit( ::arataga::utils::overloaded{
				[bytes]( out_string_view_buffer_t & b ) {
					b.increment_bytes_written( bytes );
				},
				[bytes]( out_string_buffer_t & b ) {
					b.increment_bytes_written( bytes );
				},
				[bytes]( out_fmt_memory_buffer_t & b ) {
					b.increment_bytes_written( bytes );
				}
			},
			m_piece );
	}

	[[nodiscard]]
	asio::const_buffer
	asio_buffer() const noexcept
	{
		return std::visit( ::arataga::utils::overloaded{
				[]( const out_string_view_buffer_t & b ) {
					return b.asio_buffer();
				},
				[]( const out_string_buffer_t & b ) {
					return b.asio_buffer();
				},
				[]( const out_fmt_memory_buffer_t & b ) {
					return b.asio_buffer();
				}
			},
			m_piece );
	}
};

} /* namespace arataga::acl_handler */

