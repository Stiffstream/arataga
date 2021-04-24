/*!
 * @file
 * @brief Implementation of various buffers for reading/writting of data.
 */

#pragma once

#include <arataga/acl_handler/exception.hpp>
#include <arataga/acl_handler/byte_sequence.hpp>

#include <asio/buffer.hpp>

#include <fmt/format.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <iterator>
#include <string>
#include <string_view>
#include <type_traits>

namespace arataga::acl_handler
{

//
// data_parsing_result_t
//
/*!
 * @brief Enumeration of possible parsing results.
 *
 * @note
 * This enumeration is defined in buffers.hpp because it could be necessary
 * for working with various protocols.
 */
enum class data_parsing_result_t
{
	need_more,
	success,
	invalid_data
};

//
// to_byte
//
//! Helper function for converting a value into std::byte.
template< typename T >
[[nodiscard]]
constexpr std::byte
to_byte( T v )
{
	return std::byte{ static_cast<unsigned char>(v) };
}

//
// is_byte_compatible
//
template< typename T >
struct is_byte_compatible
{
	static constexpr bool value = std::is_same_v<T, char> ||
			std::is_same_v<T, unsigned char> ||
			std::is_same_v<T, signed char> ||
			std::is_same_v<T, std::uint8_t> ||
			std::is_same_v<T, std::int8_t> ||
			std::is_same_v<T, std::byte>
			;
};

template< typename T >
inline constexpr bool is_byte_compatible_v = is_byte_compatible<T>::value;

//
// in_buffer_fixed_t
//
/*!
 * @brief Buffer of incoming data with capacity fixed at the compile-time.
 */
template< std::size_t Capacity >
class in_buffer_fixed_t
{
	//! Data buffer.
	std::array< std::byte, Capacity > m_buffer;

	//! The total count of bytes in the buffer.
	std::size_t m_size{ 0u };

	//! The position for the next read operation.
	std::size_t m_read_position{ 0u };

public:
	in_buffer_fixed_t() = default;

	//! The constructor for the case when the initial value of the buffer
	//! is already known.
	in_buffer_fixed_t( byte_sequence_t initial_content )
		:	m_size{ initial_content.size() }
	{
		if( m_size > Capacity )
			throw acl_handler_ex_t{
					fmt::format(
							"in_buffer_fixed_t: "
							"initial content doesn't fit into the buffer, "
							"Capacity: {}, initial_content.size(): {}",
							Capacity, initial_content.size() )
			};

		std::copy( initial_content.begin(), initial_content.end(),
				m_buffer.begin() );
	}

	[[nodiscard]]
	std::byte
	read_byte()
	{
		if( m_read_position >= m_size )
			throw acl_handler_ex_t{
					fmt::format( "in_buffer_fixed_t::read_byte: "
							"no more data in input buffer (size: {})",
							m_size )
			};

		return m_buffer[ m_read_position++ ];
	}

	[[nodiscard]]
	std::string
	read_bytes_as_string( std::size_t length )
	{
		return read_bytes_as_sequence( length ).to_string();
	}

	[[nodiscard]]
	byte_sequence_t
	read_bytes_as_sequence( std::size_t length )
	{
		if( m_read_position + length > m_size )
			throw acl_handler_ex_t{
					fmt::format(
							"in_buffer_fixed_t::read_bytes_as_sequence: "
							"no enough data in input buffer (size: {}, pos: {}, "
							"bytes_to_read: {})",
							m_size, m_read_position, length )
			};

		const auto bytes_to_return = std::min(
				m_size - m_read_position, length );
		const auto pos = m_read_position;
		m_read_position += bytes_to_return;

		return { &m_buffer[ pos ], bytes_to_return };
	}

	//! Take the all remaining bytes from the buffer as a string.
	[[nodiscard]]
	std::string
	read_bytes_as_string()
	{
		return read_bytes_as_string( m_size - m_read_position );
	}

	[[nodiscard]]
	std::size_t
	remaining() const noexcept
	{
		return m_size - m_read_position;
	}

	[[nodiscard]]
	std::size_t
	total_size() const noexcept
	{
		return m_size;
	}

	[[nodiscard]]
	asio::mutable_buffer
	asio_buffer() noexcept
	{
		// Read into the area starting from m_size.
		return asio::buffer( &m_buffer[ m_size ], (Capacity - m_size) );
	}

	void
	increment_bytes_read( std::size_t v )
	{
		const auto new_size = m_size + v;
		if( new_size > Capacity )
			throw acl_handler_ex_t{
				fmt::format(
						"in_buffer_fixed_t::increment_bytes_read: "
						"buffer capacity overflow, "
						"Capacity: {}, size: {}, new_size: {}",
						Capacity, m_size, new_size )
			};

		m_size = new_size;
	}

	[[nodiscard]]
	byte_sequence_t
	whole_data_as_sequence() const noexcept
	{
		return { &m_buffer[0], (&m_buffer[0]) + m_size };
	}

	[[nodiscard]]
	std::size_t
	read_position() const noexcept
	{
		return m_read_position;
	}

	void
	rewind_read_position( std::size_t pos )
	{
		if( pos > m_size )
			throw acl_handler_ex_t{
				fmt::format(
						"in_buffer_fixed_t::rewind_read_position: "
						"invalid position to rewind: {}, size: {}",
						pos, m_size )
			};

		m_read_position = pos;
	}
};

//
// in_external_buffer_t
//
/*!
 * @brief A wrapper arount an external data buffer for incoming data.
 */
class in_external_buffer_t
{
	//! External data buffer.
	std::byte * m_buffer;

	//! Max capacity of the external buffer.
	const std::size_t m_capacity;

	//! Total number of bytes in the external buffer.
	std::size_t m_size{ 0u };

	//! The position for the next read operation.
	std::size_t m_read_position{ 0u };

public:
	in_external_buffer_t( const in_external_buffer_t & ) = delete;
	in_external_buffer_t( in_external_buffer_t && ) = delete;

	//! The initializing constructor.
	/*!
	 * Intended to be used in the case when the external buffer is empty.
	 */
	template<
		typename T,
		std::enable_if_t< is_byte_compatible_v<T>, int> = 0 >
	in_external_buffer_t( T * buffer, std::size_t capacity )
		:	m_buffer{ reinterpret_cast<std::byte *>(buffer) }
		,	m_capacity{ capacity }
	{}

	//! The initializing constructor.
	/*!
	 * Intended to be used in the case when the external buffer
	 * is not empty.
	 */
	template<
		typename T,
		std::enable_if_t< is_byte_compatible_v<T>, int> = 0 >
	in_external_buffer_t(
		T * buffer,
		std::size_t capacity,
		std::size_t initial_size )
		:	m_buffer{ reinterpret_cast<std::byte *>(buffer) }
		,	m_capacity{ capacity }
		,	m_size{ initial_size }
	{
		if( initial_size > capacity )
			throw acl_handler_ex_t{
					fmt::format(
							"in_external_buffer_t: "
							"initial_size ({}) is greater than capacity ({})",
							initial_size, capacity )
			};
	}

	[[nodiscard]]
	std::byte
	read_byte()
	{
		if( m_read_position >= m_size )
			throw acl_handler_ex_t{
					fmt::format(
							"in_external_buffer_t::read_byte: "
							"no more data in input buffer (size: {})",
							m_size )
			};

		return m_buffer[ m_read_position++ ];
	}

	[[nodiscard]]
	std::string
	read_bytes_as_string( std::size_t length )
	{
		return read_bytes_as_sequence( length ).to_string();
	}

	[[nodiscard]]
	byte_sequence_t
	read_bytes_as_sequence( std::size_t length )
	{
		if( m_read_position + length > m_size )
			throw acl_handler_ex_t{
					fmt::format(
							"in_external_buffer_t::read_bytes_as_sequence: "
							"no enough data in input buffer (size: {}, pos: {}, "
							"bytes_to_read: {})",
							m_size, m_read_position, length )
			};

		const auto bytes_to_return = std::min(
				m_size - m_read_position, length );
		const auto pos = m_read_position;
		m_read_position += bytes_to_return;

		return { &m_buffer[ pos ], bytes_to_return };
	}

	//! Take the all remaining bytes from the buffer as a string.
	[[nodiscard]]
	std::string
	read_bytes_as_string()
	{
		return read_bytes_as_string( m_size - m_read_position );
	}

	[[nodiscard]]
	std::size_t
	remaining() const noexcept
	{
		return m_size - m_read_position;
	}

	[[nodiscard]]
	std::size_t
	total_size() const noexcept
	{
		return m_size;
	}

	[[nodiscard]]
	asio::mutable_buffer
	asio_buffer() noexcept
	{
		// Read into the area starting from m_size.
		return asio::buffer( &m_buffer[ m_size ], (m_capacity - m_size) );
	}

	void
	increment_bytes_read( std::size_t v )
	{
		const auto new_size = m_size + v;
		if( new_size > m_capacity )
			throw acl_handler_ex_t{
				fmt::format(
						"in_external_buffer_t::increment_bytes_read: "
						"buffer capacity overflow, "
						"capacity: {}, size: {}, new_size: {}",
						m_capacity, m_size, new_size )
			};

		m_size = new_size;
	}

	[[nodiscard]]
	byte_sequence_t
	whole_data_as_sequence() const noexcept
	{
		return { &m_buffer[0], (&m_buffer[0]) + m_size };
	}

	[[nodiscard]]
	std::size_t
	read_position() const noexcept
	{
		return m_read_position;
	}

	void
	rewind_read_position( std::size_t pos )
	{
		if( pos > m_size )
			throw acl_handler_ex_t{
				fmt::format(
						"in_external_buffer_t::rewind_read_position: "
						"invalid position to rewind: {}, size: {}",
						pos, m_size )
			};

		m_read_position = pos;
	}

	void
	reset()
	{
		m_size = 0u;
		m_read_position = 0u;
	}
};

//
// buffer_read_trx_t
//
/*!
 * @brief Helper class for organizing read-transaction from
 * an input buffer.
 *
 * Automatically returns the current read position back if
 * `commit` method wasn't called explicitely.
 *
 * That is the main usage scenarion:
 *
 * - an instance of buffer_read_trx_t created;
 * - a read operation is performed;
 * - if all required data have been read then commit() is called
 *   for buffer_read_trx_t instance;
 * - if some data is missing in the buffer then a simple return from
 *   the current scope is performed. An instance of buffer_read_trx_t
 *   return the read position back automatically.
 */
template< typename Buffer >
class buffer_read_trx_t
{
	Buffer & m_buffer;
	const std::size_t m_initial_pos;
	bool m_commited{ false };

public:
	buffer_read_trx_t( const buffer_read_trx_t & ) = delete;
	buffer_read_trx_t( buffer_read_trx_t && ) = delete;

	buffer_read_trx_t( Buffer & buffer )
		:	m_buffer{ buffer }
		,	m_initial_pos{ buffer.read_position() }
	{}

	~buffer_read_trx_t()
	{
		if( !m_commited )
			m_buffer.rewind_read_position( m_initial_pos );
	}

	void
	commit() noexcept { m_commited = true; }
};

//
// out_buffer_fixed_t
//
/*!
 * @brief Class for output buffer with the capacity fixed in the compile-time.
 */
template< std::size_t Capacity >
class out_buffer_fixed_t
{
	//! Data buffer.
	std::array< std::byte, Capacity > m_buffer;

	//! The total count of bytes in the buffer.
	std::size_t m_size{ 0u };

	//! How many bytes were sent.
	std::size_t m_bytes_written{ 0u };

public:
	out_buffer_fixed_t() = default;

	//! The initializing constructor for the case when the initial
	//! content of the buffer is already known.
	out_buffer_fixed_t( byte_sequence_t initial_content )
		:	m_size{ initial_content.size() }
	{
		if( m_size > Capacity )
			throw acl_handler_ex_t{
					fmt::format(
							"out_buffer_fixed_t: "
							"initial content doesn't fit into the buffer, "
							"Capacity: {}, initial_content.size(): {}",
							Capacity, initial_content.size() )
			};

		std::copy( initial_content.begin(), initial_content.end(),
				m_buffer.begin() );
	}

	void
	write_byte( std::byte v )
	{
		if( m_size >= Capacity )
			throw acl_handler_ex_t{
					fmt::format(
							"out_buffer_fixed_t::write_byte: "
							"no more space in output buffer (size: {}, "
							"capacity: {})",
							m_size, Capacity )
			};

		m_buffer[ m_size ] = v;
		++m_size;
	}

	void
	write_string( const std::string & v )
	{
		if( Capacity - m_size < v.size() )
			throw acl_handler_ex_t{
					fmt::format(
							"out_buffer_fixed_t::write_string: "
							"no more space in output buffer (size: {}, "
							"capacity: {}, str.size: {})",
							m_size, Capacity, v.size() )
			};

		std::transform( v.begin(), v.end(), &m_buffer[m_size],
				[]( unsigned char ch ) { return std::byte{ch}; } );

		m_size += v.size();
	}

	void
	write_string( const std::string_view & v )
	{
		if( Capacity - m_size < v.size() )
			throw acl_handler_ex_t{
					fmt::format(
							"out_buffer_fixed_t::write_string: "
							"no more space in output buffer (size: {}, "
							"capacity: {}, str.size: {})",
							m_size, Capacity, v.size() )
			};

		std::transform( v.begin(), v.end(), &m_buffer[m_size],
				[]( unsigned char ch ) { return std::byte{ch}; } );

		m_size += v.size();
	}

	template< typename T, std::size_t C >
	std::enable_if_t< is_byte_compatible_v<T>, void >
	write_bytes_from( const std::array<T, C> & arr )
	{
		if( Capacity - m_size < C )
			throw acl_handler_ex_t{
					fmt::format(
							"out_buffer_fixed_t::write_bytes_from(std::array): "
							"no more space in output buffer (size: {}, "
							"capacity: {}, arr.size: {})",
							m_size, Capacity, C )
			};

		std::transform( arr.begin(), arr.end(), &m_buffer[m_size],
				[]( auto ch ) { return std::byte{ch}; } );

		m_size += C;
	}

	// How many bytes wasn't sent yet.
	[[nodiscard]]
	std::size_t
	remaining() const noexcept
	{
		return (m_size - m_bytes_written);
	}

	[[nodiscard]]
	std::size_t
	bytes_written() const noexcept
	{
		return m_bytes_written;
	}

	[[nodiscard]]
	std::size_t
	total_size() const noexcept
	{
		return m_size;
	}

	[[nodiscard]]
	asio::const_buffer
	asio_buffer() const noexcept
	{
		// Write operation should start from m_bytes_written index.
		return asio::buffer(
				&m_buffer[ m_bytes_written ], remaining() );
	}

	void
	increment_bytes_written( std::size_t v )
	{
		const auto new_written = m_bytes_written + v;
		if( new_written > m_size )
			throw acl_handler_ex_t{
				fmt::format(
						"out_buffer_fixed_t::increment_bytes_written: "
						"buffer size overflow, "
						"Capacity: {}, size: {}, new_written: {}",
						Capacity, m_size, new_written )
			};

		m_bytes_written = new_written;
	}

	// Switch the buffer into the initial state.
	// All values are reset to 0.
	// The content of the buffer doesn't reinitialized.
	void
	reset()
	{
		m_size = 0u;
		m_bytes_written = 0u;
	}

};

//
// out_string_view_buffer_t
//
/*!
 * @brief Class of output buffer for the case when outgoing data is
 * stored inside a string_view object.
 *
 * This class is intended for simplification of writting the content
 * of string_views. Addition of a new data to a string_view object
 * isn't supported.
 */
class out_string_view_buffer_t
{
	//! Source string_view with a data.
	std::string_view m_data;

	//! How many bytes were written.
	std::size_t m_bytes_written{ 0u };

public:
	//! The default constructor.
	/*!
	 * It's necessary for the creation of an empty object that receives a value
	 * later.
	 */
	out_string_view_buffer_t()
		:	m_data{ "" }
	{}

	//! Initializing constructor.
	out_string_view_buffer_t( std::string_view data )
		:	m_data{ data }
	{}

	// How many bytes wasn't sent yet.
	[[nodiscard]]
	std::size_t
	remaining() const noexcept
	{
		return (m_data.size() - m_bytes_written);
	}

	[[nodiscard]]
	std::size_t
	bytes_written() const noexcept
	{
		return m_bytes_written;
	}

	[[nodiscard]]
	std::size_t
	total_size() const noexcept
	{
		return m_data.size();
	}

	[[nodiscard]]
	asio::const_buffer
	asio_buffer() const noexcept
	{
		// Write operation should start from m_bytes_written index.
		return asio::buffer(
				&m_data[ m_bytes_written ], remaining() );
	}

	void
	increment_bytes_written( std::size_t v )
	{
		const auto new_written = m_bytes_written + v;
		if( new_written > m_data.size() )
			throw acl_handler_ex_t{
				fmt::format( "out_string_view_buffer_t::increment_bytes_written: "
						"buffer size overflow, "
						"size: {}, new_written: {}",
						m_data.size(), new_written )
			};

		m_bytes_written = new_written;
	}
};

//
// out_string_buffer_t
//
/*!
 * @brief Class of output buffer for the case when outgoing data is
 * stored inside a string object.
 *
 * This class is intended for simplification of writting the content
 * of strings. Addition of a new data to a string object
 * isn't supported.
 */
class out_string_buffer_t
{
	//! Data to be written.
	std::string m_data;

	//! How many bytes were written.
	std::size_t m_bytes_written{ 0u };

public:
	//! The default constructor.
	/*!
	 * It's necessary for the creation of an empty object that receives a value
	 * later.
	 */
	out_string_buffer_t() = default;

	//! Initializing constructor.
	out_string_buffer_t( std::string data )
		:	m_data{ std::move(data) }
	{}

	// How many bytes wasn't sent yet.
	[[nodiscard]]
	std::size_t
	remaining() const noexcept
	{
		return (m_data.size() - m_bytes_written);
	}

	[[nodiscard]]
	std::size_t
	bytes_written() const noexcept
	{
		return m_bytes_written;
	}

	[[nodiscard]]
	std::size_t
	total_size() const noexcept
	{
		return m_data.size();
	}

	[[nodiscard]]
	asio::const_buffer
	asio_buffer() const noexcept
	{
		// Write operation should start from m_bytes_written index.
		return asio::buffer(
				&m_data[ m_bytes_written ], remaining() );
	}

	void
	increment_bytes_written( std::size_t v )
	{
		const auto new_written = m_bytes_written + v;
		if( new_written > m_data.size() )
			throw acl_handler_ex_t{
				fmt::format( "out_string_buffer_t::increment_bytes_written: "
						"buffer size overflow, "
						"size: {}, new_written: {}",
						m_data.size(), new_written )
			};

		m_bytes_written = new_written;
	}
};

//
// out_fmt_memory_buffer_t
//
/*!
 * @brief Class of output buffer for the case when outgoing data is
 * stored inside a fmt::memory_buffer object.
 *
 * This class is intended for simplification of writting the content of
 * fmt::memory_buffer. Addition of a new data to a fmt::memory_buffer object
 * isn't supported.
 */
class out_fmt_memory_buffer_t
{
	//! Data to be written.
	fmt::memory_buffer m_data;

	//! How many bytes were written.
	std::size_t m_bytes_written{ 0u };

public:
	//! The default constructor.
	/*!
	 * It's necessary for the creation of an empty object that receives a value
	 * later.
	 */
	out_fmt_memory_buffer_t() = default;

	//! Initializing constructor.
	out_fmt_memory_buffer_t( fmt::memory_buffer data )
		:	m_data{ std::move(data) }
	{}

	// How many bytes wasn't sent yet.
	[[nodiscard]]
	std::size_t
	remaining() const noexcept
	{
		return (m_data.size() - m_bytes_written);
	}

	[[nodiscard]]
	std::size_t
	bytes_written() const noexcept
	{
		return m_bytes_written;
	}

	[[nodiscard]]
	std::size_t
	total_size() const noexcept
	{
		return m_data.size();
	}

	[[nodiscard]]
	asio::const_buffer
	asio_buffer() const noexcept
	{
		// Write operation should start from m_bytes_written index.
		return asio::buffer(
				m_data.data() + m_bytes_written, remaining() );
	}

	void
	increment_bytes_written( std::size_t v )
	{
		const auto new_written = m_bytes_written + v;
		if( new_written > m_data.size() )
			throw acl_handler_ex_t{
				fmt::format( "out_fmt_memory_buffer_t::increment_bytes_written: "
						"buffer size overflow, "
						"size: {}, new_written: {}",
						m_data.size(), new_written )
			};

		m_bytes_written = new_written;
	}
};

} /* namespace arataga::acl_handler */

