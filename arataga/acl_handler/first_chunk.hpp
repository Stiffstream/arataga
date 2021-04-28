/*!
 * @file
 * @brief Type for repesentation of the first IO-chunk for a new connection.
 * @since v.0.5.0
 */

#pragma once

#include <arataga/acl_handler/exception.hpp>

#include <fmt/format.h>

#include <algorithm>
#include <cstddef>
#include <memory>

namespace arataga::acl_handler
{

//
// first_chunk_t
//
//FIXME: document this!
class first_chunk_t
{
	std::unique_ptr< std::byte[] > m_chunk;
	std::size_t m_capacity;

public:
	//NOTE: there is no default constructor!
	first_chunk_t( std::size_t capacity )
		:	m_chunk{ std::make_unique< std::byte[] >( capacity ) }
		,	m_capacity{ capacity }
	{}

	first_chunk_t( const first_chunk_t & ) = delete;
	first_chunk_t &
	operator=( const first_chunk_t & ) = delete;

	first_chunk_t( first_chunk_t && ) noexcept = default;
	first_chunk_t &
	operator=( first_chunk_t && ) noexcept = default;

	friend void
	swap( first_chunk_t & a, first_chunk_t & b ) noexcept
	{
		using std::swap;
		swap( a.m_chunk, b.m_chunk );
		swap( a.m_capacity, b.m_capacity );
	}

	[[nodiscard]]
	std::unique_ptr< std::byte[] >
	giveaway_buffer() noexcept
	{
		return std::move(m_chunk);
	}

	[[nodiscard]]
	std::byte *
	buffer() noexcept
	{
		return m_chunk.get();
	}

	[[nodiscard]]
	const std::byte *
	buffer() const noexcept
	{
		return m_chunk.get();
	}

	[[nodiscard]]
	std::size_t
	capacity() const noexcept
	{
		return m_capacity;
	}
};

//
// first_chunk_for_next_handler_t
//
//FIXME: document this!
class first_chunk_for_next_handler_t
{
	first_chunk_t m_chunk;
	std::size_t m_remaining_bytes;

public:
	first_chunk_for_next_handler_t(
		first_chunk_t chunk,
		std::size_t remaining_bytes ) noexcept
		:	m_chunk{ std::move(chunk) }
		,	m_remaining_bytes{ remaining_bytes }
	{}

	first_chunk_for_next_handler_t(
		const first_chunk_for_next_handler_t & ) = delete;
	first_chunk_for_next_handler_t &
	operator=(
		const first_chunk_for_next_handler_t & ) = delete;

	first_chunk_for_next_handler_t(
		first_chunk_for_next_handler_t && ) noexcept = default;
	first_chunk_for_next_handler_t &
	operator=(
		first_chunk_for_next_handler_t && ) noexcept = default;

	[[nodiscard]]
	first_chunk_t &
	chunk() noexcept
	{
		return m_chunk;
	}

	[[nodiscard]]
	first_chunk_t
	giveaway_chunk() noexcept
	{
		return std::move(m_chunk);
	}

	[[nodiscard]]
	std::size_t
	remaining_bytes() const noexcept
	{
		return m_remaining_bytes;
	}
};

//
// make_first_chunk_for_next_handler
//
//FIXME: document this!
/*!
 * @attention
 * It's assumed that @a consumed_bytes is not greater than @a total_bytes.
 */
[[nodiscard]]
inline first_chunk_for_next_handler_t
make_first_chunk_for_next_handler(
	first_chunk_t chunk,
	std::size_t consumed_bytes,
	std::size_t total_bytes )
{
	if( consumed_bytes > total_bytes )
		throw acl_handler_ex_t{
			fmt::format(
					"make_first_chunk_for_next_handler: "
					"consumed_bytes ({}) is greater than total_size ({})",
					consumed_bytes, total_bytes )
		};
	if( chunk.capacity() < total_bytes )
		throw acl_handler_ex_t{
			fmt::format(
					"make_first_chunk_for_next_handler: "
					"chunk's capacity ({}) too small (total_bytes: {})",
					chunk.capacity(), total_bytes )
		};

	const auto remaining = total_bytes - consumed_bytes;
	if( remaining && consumed_bytes )
	{
		// All remaining content should be shifted to the left.
		auto * b = chunk.buffer();
		std::move( b + consumed_bytes, b + total_bytes, b );
	}

	return { std::move(chunk), remaining };
}

} /* namespace arataga::acl_handler */

