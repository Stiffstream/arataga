/*!
 * @file
 * @brief Реализация различных буферов для чтения/записи данных.
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
 * Перечисление с возможными результатами попытки разобрать
 * прочитанные данные.
 *
 * Определено здесь, т.к. это перечисление может потребоваться для работы
 * с разными протоколами.
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
//! Вспомогательная функция для конвертации значения в std::byte.
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
 * @brief Класс буфера для входящих данных с фиксированной в
 * compile-time размерностью.
 */
template< std::size_t Capacity >
class in_buffer_fixed_t
{
	//! Сам буфер с данными.
	std::array< std::byte, Capacity > m_buffer;

	//! Общее количество байт, которое содержится в буфере.
	std::size_t m_size{ 0u };

	//! Позиция, с которой будет осуществляться следующее чтение.
	std::size_t m_read_position{ 0u };

public:
	in_buffer_fixed_t() = default;

	//! Конструктор для случая, когда начальное содержимое буфера
	//! уже известно.
	in_buffer_fixed_t( byte_sequence_t initial_content )
		:	m_size{ initial_content.size() }
	{
		if( m_size > Capacity )
			throw acl_handler_ex_t{
					fmt::format( "initial content doesn't fit into the buffer, "
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
			throw acl_handler_ex_t{ "no more data in input buffer" };

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
		if( m_read_position >= m_size )
			throw acl_handler_ex_t{ "no more data in input buffer" };

		const auto bytes_to_return = std::min(
				m_size - m_read_position, length );
		const auto pos = m_read_position;
		m_read_position += bytes_to_return;

		return { &m_buffer[ pos ], bytes_to_return };
	}

	//! Взять все оставшиеся байты из буфера как строку.
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
		// Читать нужно в область, которая начинается с индекса m_size.
		return asio::buffer( &m_buffer[ m_size ], (Capacity - m_size) );
	}

	void
	increment_bytes_read( std::size_t v )
	{
		const auto new_size = m_size + v;
		if( new_size > Capacity )
			throw acl_handler_ex_t{
				fmt::format( "increment_bytes_read: buffer capacity overflow, "
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
				fmt::format( "invalid position to rewind: {}, size: {}",
						pos, m_size )
			};

		m_read_position = pos;
	}
};

//
// in_external_buffer_t
//
/*!
 * @brief Класс обертки вокруг внешнего буфера для приема входящих
 * данных.
 */
class in_external_buffer_t
{
	//! Сам буфер с данными.
	std::byte * m_buffer;

	//! Максимальный объем внешнего буфера.
	const std::size_t m_capacity;

	//! Общее количество байт, которое содержится в буфере.
	std::size_t m_size{ 0u };

	//! Позиция, с которой будет осуществляться следующее чтение.
	std::size_t m_read_position{ 0u };

public:
	in_external_buffer_t( const in_external_buffer_t & ) = delete;
	in_external_buffer_t( in_external_buffer_t && ) = delete;

	//! Инициализирующий конструктор.
	/*!
	 * Предназначен для случая, когда в буфере никаких данных еще нет.
	 */
	template<
		typename T,
		std::enable_if_t< is_byte_compatible_v<T>, int> = 0 >
	in_external_buffer_t( T * buffer, std::size_t capacity )
		:	m_buffer{ reinterpret_cast<std::byte *>(buffer) }
		,	m_capacity{ capacity }
	{}

	//! Инициализирующий конструктор.
	/*!
	 * Предназначен для случая, когда в буфере уже есть какие-то данные.
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
					fmt::format( "initial_size ({}) is greater than capacity ({})",
							initial_size, capacity )
			};
	}

	[[nodiscard]]
	std::byte
	read_byte()
	{
		if( m_read_position >= m_size )
			throw acl_handler_ex_t{ "no more data in input buffer" };

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
		if( m_read_position >= m_size )
			throw acl_handler_ex_t{ "no more data in input buffer" };

		const auto bytes_to_return = std::min(
				m_size - m_read_position, length );
		const auto pos = m_read_position;
		m_read_position += bytes_to_return;

		return { &m_buffer[ pos ], bytes_to_return };
	}

	//! Взять все оставшиеся байты из буфера как строку.
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
		// Читать нужно в область, которая начинается с индекса m_size.
		return asio::buffer( &m_buffer[ m_size ], (m_capacity - m_size) );
	}

	void
	increment_bytes_read( std::size_t v )
	{
		const auto new_size = m_size + v;
		if( new_size > m_capacity )
			throw acl_handler_ex_t{
				fmt::format( "increment_bytes_read: buffer capacity overflow, "
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
				fmt::format( "invalid position to rewind: {}, size: {}",
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
 * @brief Вспомогательный класс для организации транзакции чтения
 * данных из входного буфера.
 *
 * Автоматически возвращает текущую позицию чтения для входного
 * буфера в исходное положение, если не был явно вызван метод commit.
 *
 * Идея использования этого класса следующая:
 *
 * - создается экземпляр buffer_read_trx_t;
 * - выполняется чтение из входного буфера;
 * - если из буфера прочитаны все данные, то для buffer_read_trx
 *   вызывается метод commit. Тем самым подтверждается изъятие
 *   данных из буфера;
 * - если данных во входном буфере недостаточно, то делается простой
 *   возврат из текущего скоупа. Объект buffer_read_trx вернет
 *   текущую позицию чтения в исходное положение в деструкторе.
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
 * @brief Класс буфера исходящих данных с фиксированной в
 * compile-time размерностью.
 */
template< std::size_t Capacity >
class out_buffer_fixed_t
{
	//! Сам буфер с данными.
	std::array< std::byte, Capacity > m_buffer;

	//! Общее количество байт, которое содержится в буфере.
	std::size_t m_size{ 0u };

	//! Сколько байт было отосланно из этого буфера в сокет.
	std::size_t m_bytes_written{ 0u };

public:
	out_buffer_fixed_t() = default;

	//! Конструктор для случая, когда начальное содержимое буфера
	//! уже известно.
	out_buffer_fixed_t( byte_sequence_t initial_content )
		:	m_size{ initial_content.size() }
	{
		if( m_size > Capacity )
			throw acl_handler_ex_t{
					fmt::format( "initial content doesn't fit into the buffer, "
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
			throw acl_handler_ex_t{ "no more space in output buffer" };

		m_buffer[ m_size ] = v;
		++m_size;
	}

	void
	write_string( const std::string & v )
	{
		if( Capacity - m_size < v.size() )
			throw acl_handler_ex_t{ "no enought space in output buffer" };

		std::transform( v.begin(), v.end(), &m_buffer[m_size],
				[]( unsigned char ch ) { return std::byte{ch}; } );

		m_size += v.size();
	}

	void
	write_string( const std::string_view & v )
	{
		if( Capacity - m_size < v.size() )
			throw acl_handler_ex_t{ "no enought space in output buffer" };

		std::transform( v.begin(), v.end(), &m_buffer[m_size],
				[]( unsigned char ch ) { return std::byte{ch}; } );

		m_size += v.size();
	}

	template< typename T, std::size_t C >
	std::enable_if_t< is_byte_compatible_v<T>, void >
	write_bytes_from( const std::array<T, C> & arr )
	{
		if( Capacity - m_size < C )
			throw acl_handler_ex_t{ "no enought space in output buffer" };

		std::transform( arr.begin(), arr.end(), &m_buffer[m_size],
				[]( auto ch ) { return std::byte{ch}; } );

		m_size += C;
	}

	// Сколько байт еще не было отослано в сокет.
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
		// Записывать нужно содержимое с индекса m_bytes_written.
		return asio::buffer(
				&m_buffer[ m_bytes_written ], remaining() );
	}

	void
	increment_bytes_written( std::size_t v )
	{
		const auto new_written = m_bytes_written + v;
		if( new_written > m_size )
			throw acl_handler_ex_t{
				fmt::format( "increment_bytes_written: buffer size overflow, "
						"Capacity: {}, size: {}, new_written: {}",
						Capacity, m_size, new_written )
			};

		m_bytes_written = new_written;
	}

	// Перевод буфера в начальное состояние.
	// Все значения сбрасываются в 0.
	// Содержимое буфера ничем не переинициализируется.
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
 * @brief Класс буфера исходящих данных, который представлен объектом
 * string_view.
 *
 * Этот класс предназначен для упрощения записи содержимого string_view
 * в сокет. Запись новых данных в string_view объект не поддерживается.
 */
class out_string_view_buffer_t
{
	//! Исходный string_view с данными.
	std::string_view m_data;

	//! Сколько байт было отосланно из этого буфера в сокет.
	std::size_t m_bytes_written{ 0u };

public:
	//! Пустой конструктор так же нужен.
	/*!
	 * Для создания объектов, которые пока не имеют никакого содержимого.
	 */
	out_string_view_buffer_t()
		:	m_data{ "" }
	{}

	//! Инициализирующий конструктор.
	out_string_view_buffer_t( std::string_view data )
		:	m_data{ data }
	{}

	// Сколько байт еще не было отослано в сокет.
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
		// Записывать нужно содержимое с индекса m_bytes_written.
		return asio::buffer(
				&m_data[ m_bytes_written ], remaining() );
	}

	void
	increment_bytes_written( std::size_t v )
	{
		const auto new_written = m_bytes_written + v;
		if( new_written > m_data.size() )
			throw acl_handler_ex_t{
				fmt::format( "increment_bytes_written: buffer size overflow, "
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
 * @brief Класс буфера исходящих данных, который представлен объектом
 * string.
 *
 * Этот класс предназначен для упрощения записи содержимого string
 * в сокет. Запись новых данных в string объект не поддерживается.
 */
class out_string_buffer_t
{
	//! Данные, которые нужно записать в сокет.
	std::string m_data;

	//! Сколько байт было отосланно из этого буфера в сокет.
	std::size_t m_bytes_written{ 0u };

public:
	//! Пустой конструктор так же нужен.
	/*!
	 * Для создания объектов, которые пока не имеют никакого содержимого.
	 */
	out_string_buffer_t() = default;

	//! Инициализирующий конструктор.
	out_string_buffer_t( std::string data )
		:	m_data{ std::move(data) }
	{}

	// Сколько байт еще не было отослано в сокет.
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
		// Записывать нужно содержимое с индекса m_bytes_written.
		return asio::buffer(
				&m_data[ m_bytes_written ], remaining() );
	}

	void
	increment_bytes_written( std::size_t v )
	{
		const auto new_written = m_bytes_written + v;
		if( new_written > m_data.size() )
			throw acl_handler_ex_t{
				fmt::format( "increment_bytes_written: buffer size overflow, "
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
 * @brief Класс буфера исходящих данных, который представлен объектом
 * fmt::memory_buffer.
 *
 * Этот класс предназначен для упрощения записи содержимого
 * fmt::memory_buffer в сокет. Запись новых данных в fmt::memory_buffer
 * объект не поддерживается.
 */
class out_fmt_memory_buffer_t
{
	//! Данные, которые нужно записать в сокет.
	fmt::memory_buffer m_data;

	//! Сколько байт было отосланно из этого буфера в сокет.
	std::size_t m_bytes_written{ 0u };

public:
	//! Пустой конструктор так же нужен.
	/*!
	 * Для создания объектов, которые пока не имеют никакого содержимого.
	 */
	out_fmt_memory_buffer_t() = default;

	//! Инициализирующий конструктор.
	out_fmt_memory_buffer_t( fmt::memory_buffer data )
		:	m_data{ std::move(data) }
	{}

	// Сколько байт еще не было отослано в сокет.
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
		// Записывать нужно содержимое с индекса m_bytes_written.
		return asio::buffer(
				m_data.data() + m_bytes_written, remaining() );
	}

	void
	increment_bytes_written( std::size_t v )
	{
		const auto new_written = m_bytes_written + v;
		if( new_written > m_data.size() )
			throw acl_handler_ex_t{
				fmt::format( "increment_bytes_written: buffer size overflow, "
						"size: {}, new_written: {}",
						m_data.size(), new_written )
			};

		m_bytes_written = new_written;
	}
};

} /* namespace arataga::acl_handler */

