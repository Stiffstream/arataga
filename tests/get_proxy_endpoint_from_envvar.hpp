#include <asio/ip/tcp.hpp>

#include <fmt/format.h>

#include <charconv>
#include <cstdlib>
#include <string_view>
#include <string>
#include <system_error>

[[nodiscard]]
inline asio::ip::tcp::endpoint
get_proxy_endpoint_from_envvar(
	const char * env_var_name )
{
	const char * raw_value = std::getenv(env_var_name);
	if( !raw_value )
		throw std::runtime_error{
				fmt::format( "There is no environment variable '{}'",
						env_var_name )
		};

	std::string_view value{ raw_value };
	// Have to find port number.
	const auto colon_pos = value.find( ':' );
	if( colon_pos == std::string_view::npos )
		throw std::runtime_error{
				fmt::format( "There is no port number in '{}'", value )
		};

	auto ipv4_addr = asio::ip::make_address_v4( value.substr( 0, colon_pos ) );

	value.remove_prefix( colon_pos + 1u );

	unsigned short port;
	const auto [p, ec] = std::from_chars(
			&value[0], (&value[0]) + value.size(), port);
	if( ec != std::errc() )
		throw std::runtime_error{
				fmt::format( "Unable to parse port value '{}': {}",
						value,
						std::make_error_code(ec).message() )
		};

	return { ipv4_addr, port };
}

