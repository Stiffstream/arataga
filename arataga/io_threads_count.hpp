/*!
 * @file
 * @brief Types for representation number of IO-threads.
 * @since v.0.3.1
 */

#pragma once

#include <variant>
#include <iostream>
#include <thread>
#include <string>

#include <fmt/format.h>

namespace arataga
{

namespace io_threads_count
{

//
// default_t
//
//! Type for the case when the default algorithm for calculation
//! of number of CPU cores for serving IO-threads.
/*!
 * @since v.0.3.1
 */
struct default_t
{
	[[nodiscard]]
	std::size_t
	detect() const noexcept
	{
		// If there are many CPUs then two of them will be left for the OS
		// and admin parts of arataga. All other CPUs will be allocated
		// for IO-threads.
		const auto cpus = std::thread::hardware_concurrency();
		return (cpus > 2u ? (cpus - 2u) : 1u);
	}

	[[nodiscard]]
	std::string
	to_string() const
	{
		return fmt::format( "(auto:default(nCPU-2):{})", detect() );
	}
};

//
// exact_t
//
//! Type for the case when the number of IO-threads is specified
//! by a user.
/*!
 * @since v.0.3.1
 */
struct exact_t
{
	std::size_t m_number;

	[[nodiscard]]
	std::size_t
	detect() const noexcept
	{
		return m_number;
	}

	[[nodiscard]]
	std::string
	to_string() const
	{
		return fmt::format( "(exact:{})", detect() );
	}
};

//
// all_cores_t
//
//! Type for the case when all CPU cores should be allocated
//! for serving IO-threads.
/*!
 * @since v.0.3.1
 */
struct all_cores_t
{
	[[nodiscard]]
	std::size_t
	detect() const noexcept
	{
		const auto cpus = std::thread::hardware_concurrency();
		return (cpus == 0u ? 1u : cpus);
	}

	[[nodiscard]]
	std::string
	to_string() const
	{
		return fmt::format( "(auto:all_cores:{})", detect() );
	}
};

} /* namespace io_threads_count */

//
// io_threads_count_t
//
//! Type for number of IO-threads.
/*!
 * @since v.0.3.1
 */
using io_threads_count_t = std::variant<
	io_threads_count::default_t,
	io_threads_count::exact_t,
	io_threads_count::all_cores_t
>;

[[nodiscard]]
inline std::string
to_string( const io_threads_count_t & v )
{
	return std::visit(
			[]( const auto & item ) -> std::string { return item.to_string(); },
			v );
}

} /* namespace arataga */

template<>
struct fmt::formatter< arataga::io_threads_count_t > 
	: fmt::formatter< std::string >
{
	template< typename FormatContext >
	auto format(
		const arataga::io_threads_count_t & tc,
		FormatContext & ctx )
	{
		const auto str = arataga::to_string(tc);
		return fmt::formatter< std::string >::format( str, ctx );
	}
};

