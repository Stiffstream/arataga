/*!
 * @file
 * @brief Helper function for loading the whole file content into memory.
 */

#pragma once

#include <arataga/utils/ensure_successful_syscall.hpp>

#include <arataga/exception.hpp>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <vector>

namespace arataga::utils
{

// An exception is throw in the case of the absecense of file or
// if there is some error.
[[nodiscard]]
inline std::vector< char >
load_file_into_memory(
	const std::filesystem::path & file_name )
{
	std::vector< char > buffer;

	const auto file_size = std::filesystem::file_size( file_name );
	if( file_size )
	{
		std::ifstream file;
		file.open( file_name, std::ios_base::in | std::ios_base::binary );
		if( !file )
			ensure_successful_syscall( -1,
					fmt::format( "trying to open file '{}'", file_name ).c_str() );

		file.exceptions( std::ifstream::badbit | std::ifstream::failbit );

		buffer.resize( file_size );
		file.read( buffer.data(), static_cast<std::streamsize>(file_size) );

		if( file.gcount() != static_cast<std::streamsize>(file_size) )
			throw std::runtime_error{
					fmt::format( "number of bytes loaded mismatches the size of "
							"the file: bytes_loaded={}, file_size={}",
							file.gcount(),
							file_size )
				};
	}

	return buffer;
}

} /* namespace arataga::utils */

