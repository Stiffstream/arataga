/*!
 * @file
 * @brief Stuff for working with configuration.
 */

#include <arataga/config.hpp>

#include <arataga/utils/spdlog_log_levels.hpp>
#include <arataga/utils/overloaded.hpp>
#include <arataga/utils/line_extractor.hpp>
#include <arataga/utils/line_reader.hpp>
#include <arataga/utils/ip_address_parsers.hpp>
#include <arataga/utils/transfer_speed_parser.hpp>

#include <restinio/helpers/http_field_parsers/basics.hpp>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <variant>

namespace arataga
{

namespace parse_config_impl
{

struct success_t {};

class failure_t
{
	std::string m_description;

public:
	failure_t( std::string description )
		:	m_description{ std::move(description) }
	{}

	[[nodiscard]]
	std::string_view
	description() const noexcept { return { m_description }; }
};

using command_handling_result_t = std::variant< success_t, failure_t >;

class command_handler_t
{
protected :
	template< typename Parser, typename Parsing_Result_Handler >
	[[nodiscard]]
	static command_handling_result_t
	perform_parsing(
		std::string_view content,
		Parser && parser,
		Parsing_Result_Handler && result_handler )
	{
		using namespace restinio::easy_parser;

		auto parse_result = try_parse(
				content,
				std::forward<Parser>(parser) );
		if( !parse_result )
			return failure_t{
					fmt::format( "unable to parse argument: {}",
							make_error_description( parse_result.error(), content ) )
			};
		else
			return result_handler( *parse_result );
	}

public:
	virtual ~command_handler_t() = default;

	[[nodiscard]]
	virtual command_handling_result_t
	try_handle(
		std::string_view content,
		config_t & current_cfg ) const = 0;
};

using command_handler_unique_ptr_t = std::unique_ptr< command_handler_t >;

//! Type for storing number of file line.
using line_number_t = ::arataga::utils::line_extractor_t::line_number_t;

namespace parsers
{

//
// timeout_value_p
//
/*!
 * @brief A producer for easy_parser that extracts time-out values
 * with possible suffixes (ms, s, min).
 */
[[nodiscard]]
static auto
timeout_value_p()
{
	struct tmp_value_t
	{
		std::int_least64_t m_count{ 0 };
		int m_multiplier{ 1000 };
	};

	using namespace restinio::http_field_parsers;

	return produce< std::chrono::milliseconds >(
			produce< tmp_value_t >(
				non_negative_decimal_number_p< std::int_least64_t >()
						>> &tmp_value_t::m_count,
				maybe(
					produce< int >(
						alternatives(
							exact_p( "min" ) >> just_result( 60'000 ),
							exact_p( "s" ) >> just_result( 1'000 ),
							exact_p( "ms" ) >> just_result( 1 )
						)
					) >> &tmp_value_t::m_multiplier
				)
			)
			>> convert( []( const auto tmp ) {
					std::chrono::milliseconds r{ tmp.m_count };
					return r * tmp.m_multiplier;
				} )
			>> as_result()
		);
}

//
// byte_count_p
//
/*!
 * @brief A producer for easy_parser that extracts count of bytes
 * with possible suffixes (b, kib, mib, gib).
 *
 * The producer makes values of type bandlim_config_t::value_t.
 */
[[nodiscard]]
static auto
byte_count_p()
{
	using value_t = bandlim_config_t::value_t;

	struct tmp_value_t
	{
		value_t m_count{ 0u };
		value_t m_multiplier{ 1u };
	};

	using namespace restinio::http_field_parsers;

	return produce< value_t >(
			produce< tmp_value_t >(
				non_negative_decimal_number_p< value_t >()
						>> &tmp_value_t::m_count,
				maybe(
					produce< value_t >(
						alternatives(
							expected_caseless_token_p( "gib" )
									>> just_result( 1024ul * 1024ul * 1024ul ),
							expected_caseless_token_p( "mib" )
									>> just_result( 1024ul * 1024ul ),
							expected_caseless_token_p( "kib" )
									>> just_result( 1024ul ),
							expected_caseless_token_p( "b" )
									>> just_result( 1 )
						)
					) >> &tmp_value_t::m_multiplier
				)
			)
			>> convert( []( const auto tmp ) {
					return tmp.m_count * tmp.m_multiplier;
				} )
			>> as_result()
		);
}

} /* namespace parsers */

//
// log_level_handler_t
//
/*!
 * @brief Handler for `log_level` command.
 */
class log_level_handler_t : public command_handler_t
{
public:
	command_handling_result_t
	try_handle(
		std::string_view content,
		config_t & current_cfg ) const override
	{
		using namespace restinio::http_field_parsers;

		return perform_parsing(
			content,
			token_p(),
			[&]( const std::string & level_name ) -> command_handling_result_t {
				const auto opt_level = arataga::utils::name_to_spdlog_level_enum(
						level_name );
				if( !opt_level )
					return failure_t{
							fmt::format( "unsupported log-level: {}", level_name )
					};

				current_cfg.m_log_level = *opt_level;

				return success_t{};
			} );
	}
};

//
// dns_cache_cleanup_period_handler_t
//
/*!
 * @brief Handler for `dns_cache_cleanup_period` command.
 */
class dns_cache_cleanup_period_handler_t : public command_handler_t
{
public:
	command_handling_result_t
	try_handle(
		std::string_view content,
		config_t & current_cfg ) const override
	{
		using namespace restinio::http_field_parsers;

		return perform_parsing(
			content,
			parsers::timeout_value_p(),
			[&]( std::chrono::milliseconds v ) -> command_handling_result_t {
				if( std::chrono::milliseconds::zero() == v )
				{
					return failure_t{ "dns_cache_cleanup_period can't be 0" };
				}

				current_cfg.m_dns_cache_cleanup_period = v;

				return success_t{};
			} );
	}
};

//
// maxconn_handler_t
//
/*!
 * @brief Handler for `acl.max.conn` command.
 */
class maxconn_handler_t : public command_handler_t
{
public:
	command_handling_result_t
	try_handle(
		std::string_view content,
		config_t & current_cfg ) const override
	{
		using namespace restinio::http_field_parsers;

		return perform_parsing(
			content,
			non_negative_decimal_number_p< unsigned int >(),
			[&]( unsigned int v ) -> command_handling_result_t {
				if( 0u == v )
					return failure_t{ "acl.max.conn can't be 0" };

				current_cfg.m_common_acl_params.m_maxconn = v;

				return success_t{};
			} );
	}
};

//
// denied_ports_handler_t
//
/*!
 * @brief Handler for `denied_ports` command.
 */
class denied_ports_handler_t : public command_handler_t
{
	using dp = denied_ports_config_t;

	//! Checks for validity of all ranges.
	/*!
	 * The left border of a range should be no greater than the right border.
	 */
	[[nodiscard]]
	static std::optional< failure_t >
	check_range_validity(
		const dp::case_container_t & cases )
	{
		for( const auto & c : cases )
		{
			if( const auto * r = std::get_if< dp::ports_range_case_t >(&c);
					r && (r->m_low > r->m_high) )
			{
				return failure_t{
						fmt::format( "invalid ports range: {}-{}",
								r->m_low, r->m_high )
					};
			}
		}

		return std::nullopt;
	}

public:
	command_handling_result_t
	try_handle(
		std::string_view content,
		config_t & current_cfg ) const override
	{
		using namespace restinio::http_field_parsers;

		const auto single_case_p = produce< dp::denied_case_t >(
				alternatives(
					produce< dp::ports_range_case_t >(
						non_negative_decimal_number_p< dp::port_t >()
								>> &dp::ports_range_case_t::m_low,
						ows(),
						symbol('-'),
						ows(),
						non_negative_decimal_number_p< dp::port_t >()
								>> &dp::ports_range_case_t::m_high
					) >> as_result(),
					produce< dp::single_port_case_t >(
						non_negative_decimal_number_p< dp::port_t >()
								>> &dp::single_port_case_t::m_port
					) >> as_result()
				)
			);

		const auto all_cases_p = produce< dp::case_container_t >(
				single_case_p >> to_container(),
				repeat( 0u, N,
					ows(),
					symbol(','),
					ows(),
					single_case_p >> to_container() ),
				maybe( ows(), symbol(',') )
			);

		return perform_parsing(
			content,
			all_cases_p,
			[&]( auto & container ) -> command_handling_result_t {
				// If there are ranges they should be valid.
				auto check_result = check_range_validity( container );
				if( check_result )
					return std::move( *check_result );

				current_cfg.m_denied_ports = denied_ports_config_t{
					std::move(container)
				};

				return success_t{};
			} );
	}
};

//
// timeout_handler_t
//
/*!
 * @brief Handler for `failed_auth_reply_timeout` command.
 */
template< std::chrono::milliseconds common_acl_params_t::*Field >
class timeout_handler_t : public command_handler_t
{
public:
	command_handling_result_t
	try_handle(
		std::string_view content,
		config_t & current_cfg ) const override
	{
		using namespace restinio::http_field_parsers;

		return perform_parsing(
			content,
			parsers::timeout_value_p(),
			[&]( std::chrono::milliseconds v ) -> command_handling_result_t {
				current_cfg.m_common_acl_params.*Field = v;

				return success_t{};
			} );
	}
};

//
// bandlim_single_value_handler_t
//
/*!
 * @brief Handler for `bandlimin.in`, `bandlim.out` commands.
 */
template< bandlim_config_t::value_t bandlim_config_t::*Field >
class bandlim_single_value_handler_t : public command_handler_t
{
public:
	command_handling_result_t
	try_handle(
		std::string_view content,
		config_t & current_cfg ) const override
	{
		using namespace restinio::http_field_parsers;

		return perform_parsing(
			content,
			arataga::utils::parsers::transfer_speed_p(),
			[&]( auto v ) -> command_handling_result_t {
				current_cfg.m_common_acl_params.m_client_bandlim.*Field = v;
				return success_t{};
			} );
	}
};

//
// io_chunk_size_t
//
/*!
 * @brief Handler for `io_chunk_size` command.
 */
class io_chunk_size_handler_t : public command_handler_t
{
public:
	command_handling_result_t
	try_handle(
		std::string_view content,
		config_t & current_cfg ) const override
	{
		using namespace restinio::http_field_parsers;

		return perform_parsing(
			content,
			parsers::byte_count_p(),
			[&]( auto v ) -> command_handling_result_t {
				if( 0u == v )
					return failure_t{
							fmt::format( "io_chunk_size can't be 0" )
					};

				current_cfg.m_common_acl_params.m_io_chunk_size =
						static_cast< std::size_t >( v );
				return success_t{};
			} );
	}
};

//
// io_chunk_count_handler_t
//
/*!
 * @brief Handler for `acl.io.chunk_count` command.
 */
class io_chunk_count_handler_t : public command_handler_t
{
public:
	command_handling_result_t
	try_handle(
		std::string_view content,
		config_t & current_cfg ) const override
	{
		using namespace restinio::http_field_parsers;

		return perform_parsing(
			content,
			non_negative_decimal_number_p< std::size_t >(),
			[&]( std::size_t v ) -> command_handling_result_t {
				if( 0u == v )
					return failure_t{ "acl.io.chunk_count can't be 0" };

				current_cfg.m_common_acl_params.m_io_chunk_count = v;

				return success_t{};
			} );
	}
};
namespace acl_handler_details
{

struct in_port_t { acl_config_t::port_t m_port; };

struct in_ip_t { asio::ip::address_v4 m_addr; };

struct out_ip_t { asio::ip::address m_addr; };

using parsed_parameter_t = std::variant<
		in_port_t,
		in_ip_t,
		out_ip_t >;

using parameters_container_t = std::vector< parsed_parameter_t >;

struct parsed_description_t
{
	acl_protocol_t m_protocol;
	parameters_container_t m_parameters;
};

[[nodiscard]]
static inline auto
make_parser()
{
	using namespace restinio::http_field_parsers;

	const auto in_port_p = []{
		return produce< in_port_t >(
				exact( "port" ),
				ows(),
				symbol( '=' ),
				ows(),
				non_negative_decimal_number_p< acl_config_t::port_t >()
						>> &in_port_t::m_port
			);
	};
	const auto in_ip_p = []{
		return produce< in_ip_t >(
				exact( "in_ip" ),
				ows(),
				symbol( '=' ),
				ows(),
				arataga::utils::parsers::ipv4_address_p() >> &in_ip_t::m_addr
			);
	};
	const auto out_ip_p = []{
		return produce< out_ip_t >(
				exact( "out_ip" ),
				ows(),
				symbol( '=' ),
				ows(),
				arataga::utils::parsers::ip_address_p() >> &out_ip_t::m_addr
			);
	};
	const auto parsed_parameter_p = [&]{
		return produce< parsed_parameter_t >(
				alternatives(
					in_port_p() >> as_result(),
					in_ip_p() >> as_result(),
					out_ip_p() >> as_result()
				)
			);
	};

	return produce< parsed_description_t >(
			produce< acl_protocol_t >(
				alternatives(
					exact_p( "auto" ) >> just_result( acl_protocol_t::autodetect ),
					exact_p( "socks" ) >> just_result( acl_protocol_t::socks ),
					exact_p( "http" ) >> just_result( acl_protocol_t::http )
				)
			) >> &parsed_description_t::m_protocol,
			ows(),
			symbol( ',' ),
			ows(),
			produce< parameters_container_t >(
				parsed_parameter_p() >> to_container(),
				repeat( 0u, N,
					ows(),
					symbol( ',' ),
					ows(),
					parsed_parameter_p() >> to_container()
				),
				maybe( ows(), symbol( ',' ) )
			) >> &parsed_description_t::m_parameters
		);
}

} /* namespace acl_handler_details */

//
// acl_handler_t
//
/*!
 * @brief Handler for `acl` command.
 */
class acl_handler_t : public command_handler_t
{
	using parser_t = decltype(acl_handler_details::make_parser());

	//! The actual parser of ACL parameters.
	/*!
	 * It's created as a class member to avoid recreation of it for
	 * every 'acl' command in a file.
	 */
	const parser_t m_parser = acl_handler_details::make_parser();

	struct parameters_handler_t
	{
		std::optional< acl_config_t::port_t > m_port;
		std::optional< asio::ip::address_v4 > m_in_ip;
		std::optional< asio::ip::address > m_out_ip;

		command_handling_result_t
		operator()( const acl_handler_details::in_port_t & port )
		{
			if( m_port )
				return failure_t{ "port parameter is already set" };

			m_port = port.m_port;
			return success_t{};
		}

		command_handling_result_t
		operator()( const acl_handler_details::in_ip_t & ip )
		{
			if( m_in_ip )
				return failure_t{ "in_ip parameter is already set" };

			m_in_ip = ip.m_addr;
			return success_t{};
		}

		command_handling_result_t
		operator()( const acl_handler_details::out_ip_t & ip )
		{
			if( m_out_ip )
				return failure_t{ "out_ip parameter is already set" };

			m_out_ip = ip.m_addr;
			return success_t{};
		}
	};

public:
	command_handling_result_t
	try_handle(
		std::string_view content,
		config_t & current_cfg ) const override
	{
		namespace hd = acl_handler_details;

		return perform_parsing(
			content,
			m_parser,
			[&]( const hd::parsed_description_t & desc ) -> command_handling_result_t
			{
				// Check the validity of parameters.
				// Convert IP-addresses from textual form into instances
				// of asio::ip::address.
				parameters_handler_t params_handler;
				for( const auto & p : desc.m_parameters )
				{
					auto r = std::visit( params_handler, p );
					if( auto * f = std::get_if< failure_t >( &r ) )
						return std::move(*f);
				}

				// All mandatory parameters should be specified.
				if( !params_handler.m_port )
					return failure_t{ "port is not specified" };
				if( !params_handler.m_in_ip )
					return failure_t{ "in_ip is not specified" };
				if( !params_handler.m_out_ip )
					return failure_t{ "out_ip is not specified" };

				// Now we can make the description of a new ACL.
				current_cfg.m_acls.emplace_back(
						desc.m_protocol,
						*(params_handler.m_port),
						*(params_handler.m_in_ip),
						*(params_handler.m_out_ip) );

				return success_t{};
			} );
	}
};

//
// http_msg_limits_single_value_handler_t
//
/*!
 * @brief Command handler for HTTP-related constraints.
 */
template< std::size_t http_message_value_limits_t::*Field >
class http_msg_limits_single_value_handler_t : public command_handler_t
{
public:
	command_handling_result_t
	try_handle(
		std::string_view content,
		config_t & current_cfg ) const override
	{
		using namespace restinio::http_field_parsers;

		return perform_parsing(
			content,
			parsers::byte_count_p(),
			[&]( auto v ) -> command_handling_result_t {
				if( 0u == v )
					return failure_t{
							fmt::format( "size limit can't be 0" )
					};

				current_cfg.m_common_acl_params
						.m_http_message_limits.*Field = v;

				return success_t{};
			} );
	}
};

//
// nserver_handler_t
//
/*!
 * @brief Handler for `nserver` command.
 */
class nserver_handler_t : public command_handler_t
{
public:
	command_handling_result_t
	try_handle(
		std::string_view content,
		config_t & current_cfg ) const override
	{
		using namespace restinio::http_field_parsers;

		using ipv4_addr_container_t = std::vector< asio::ip::address_v4 >;

		using arataga::utils::parsers::ipv4_address_p;

		const auto address_list_p = produce< ipv4_addr_container_t >(
				ipv4_address_p() >> to_container(),
				repeat( 0u, N,
					ows(),
					symbol(','),
					ows(),
					ipv4_address_p() >> to_container() ),
				maybe( ows(), symbol(',') )
			);

		return perform_parsing(
			content,
			address_list_p,
			[&]( auto & container ) -> command_handling_result_t {
				// List of new IPs should be added to the existing values.
				std::transform(
						std::begin(container), std::end(container),
						std::back_inserter(current_cfg.m_nameserver_ips),
						[]( asio::ip::address_v4 v ) -> asio::ip::address {
							return { v };
						} );

				return success_t{};
			} );
	}
};

//
// spaces
//
//! Set of space symbols.
[[nodiscard]]
inline constexpr std::string_view
spaces() noexcept { return { " \t\x0b" }; }

//
// line_extractor_t
//
using line_extractor_t = ::arataga::utils::line_extractor_t;

//
// line_reader_t
//
using line_reader_t = ::arataga::utils::line_reader_t;

/*!
 * @brief Splits specified line into the command and optional part
 * with arguments.
 *
 * @attention
 * It's expected that @a line contains something other than spaces.
 *
 * @return A tuple where the first item is the command name, and the second
 * is the optional part with arguments (the second item can be empty).
 */
[[nodiscard]]
std::tuple< std::string_view, std::string_view >
split_line( std::string_view line )
{
	const auto command_start = line.find_first_not_of( spaces() );
	if( std::string_view::npos == command_start )
		throw config_parser_t::parser_exception_t(
				"split_line: only spaces in the input" );

	// The second part of line after extraction the command name.
	// Maybe empty.
	std::string_view args;

	const auto line_size = line.size();
	const auto command_end = std::min(
			line.find_first_of( spaces(), command_start ),
			line_size );
	if( line_size != command_end )
	{
		// There is something other than command.
		// Leading spaces should be removed.
		if( const auto spaces_end = std::min(
				line.find_first_not_of( spaces(), command_end ),
				line_size );
				line_size != spaces_end )
		{
			args = line.substr( spaces_end );
		}
	}

	std::string_view command = line.substr(
			command_start,
			command_end - command_start );

	return { command, args };
}

} /* namespace parse_config_impl */

std::ostream &
operator<<( std::ostream & to, acl_protocol_t proto )
{
	const auto n = [proto]() noexcept -> const char * {
		const char * r = "unknown";
		switch( proto )
		{
			case acl_protocol_t::autodetect: r = "auto"; break;
			case acl_protocol_t::socks: r = "socks"; break;
			case acl_protocol_t::http: r = "http"; break;
		}
		return r;
	};

	return (to << n());
}

std::ostream &
operator<<( std::ostream & to, const acl_config_t & acl )
{
	fmt::print( to, "{}, port={}, in_ip={}, out_ip={}",
			acl.m_protocol,
			acl.m_port,
			acl.m_in_addr,
			acl.m_out_addr );

	return to;
}

//
// config_parser_t::parser_exception_t
//
config_parser_t::parser_exception_t::parser_exception_t(
	const std::string & what )
	:	exception_t{ "config_parser: " + what }
{}

//
// config_parser_t::impl_t
//
struct config_parser_t::impl_t
{
	using command_map_t = std::map<
			std::string,
			parse_config_impl::command_handler_unique_ptr_t,
			std::less<> >;

	command_map_t m_commands;

	/*!
	 * @return nullptr, if command handler isn't found.
	 */
	[[nodiscard]]
	const parse_config_impl::command_handler_t *
	find_command_handler( std::string_view name ) const noexcept
	{
		const auto it = m_commands.find( name );
		if( it != m_commands.end() )
			return it->second.get();
		else
			return nullptr;
	}
};

//
// config_parser_t
//
config_parser_t::config_parser_t()
	:	m_impl{ new impl_t{} }
{
	using namespace parse_config_impl;
	using namespace std::string_literals;

	m_impl->m_commands.emplace(
			"log_level"s,
			std::make_unique< log_level_handler_t >() );

	m_impl->m_commands.emplace(
			"dns_cache_cleanup_period"s,
			std::make_unique< dns_cache_cleanup_period_handler_t >() );
	m_impl->m_commands.emplace(
			"nserver"s,
			std::make_unique< nserver_handler_t >() );

	m_impl->m_commands.emplace(
			"bandlim.in"s,
			std::make_unique<
					bandlim_single_value_handler_t<
							&bandlim_config_t::m_in >
			>() );
	m_impl->m_commands.emplace(
			"bandlim.out"s,
			std::make_unique<
					bandlim_single_value_handler_t<
							&bandlim_config_t::m_out >
			>() );

	m_impl->m_commands.emplace(
			"denied_ports"s,
			std::make_unique< denied_ports_handler_t >() );

	m_impl->m_commands.emplace(
			"timeout.failed_auth_reply"s,
			std::make_unique<
					timeout_handler_t<
							&common_acl_params_t::m_failed_auth_reply_timeout
					>
			>() );
	m_impl->m_commands.emplace(
			"timeout.protocol_detection"s,
			std::make_unique<
					timeout_handler_t<
							&common_acl_params_t::m_protocol_detection_timeout
					>
			>() );
	m_impl->m_commands.emplace(
			"timeout.socks.handshake"s,
			std::make_unique<
					timeout_handler_t<
							&common_acl_params_t::m_socks_handshake_phase_timeout
					>
			>() );
	m_impl->m_commands.emplace(
			"timeout.dns_resolving"s,
			std::make_unique<
					timeout_handler_t<
							&common_acl_params_t::m_dns_resolving_timeout
					>
			>() );
	m_impl->m_commands.emplace(
			"timeout.authentification"s,
			std::make_unique<
					timeout_handler_t<
							&common_acl_params_t::m_authentification_timeout
					>
			>() );
	m_impl->m_commands.emplace(
			"timeout.connect_target"s,
			std::make_unique<
					timeout_handler_t<
							&common_acl_params_t::m_connect_target_timeout
					>
			>() );
	m_impl->m_commands.emplace(
			"timeout.socks.bind"s,
			std::make_unique<
					timeout_handler_t<
							&common_acl_params_t::m_socks_bind_timeout
					>
			>() );
	m_impl->m_commands.emplace(
			"timeout.idle_connection"s,
			std::make_unique<
					timeout_handler_t<
							&common_acl_params_t::m_idle_connection_timeout
					>
			>() );
	m_impl->m_commands.emplace(
			"timeout.http.headers_complete"s,
			std::make_unique<
					timeout_handler_t<
							&common_acl_params_t::m_http_headers_complete_timeout
					>
			>() );
	m_impl->m_commands.emplace(
			"timeout.http.negative_response"s,
			std::make_unique<
					timeout_handler_t<
							&common_acl_params_t::m_http_negative_response_timeout
					>
			>() );

	m_impl->m_commands.emplace(
			"acl.max.conn"s,
			std::make_unique< maxconn_handler_t >() );
	m_impl->m_commands.emplace(
			"acl.io.chunk_size"s,
			std::make_unique< io_chunk_size_handler_t >() );
	m_impl->m_commands.emplace(
			"acl.io.chunk_count"s,
			std::make_unique< io_chunk_count_handler_t >() );

	m_impl->m_commands.emplace(
			"http.limits.request_target"s,
			std::make_unique<
					http_msg_limits_single_value_handler_t<
							&http_message_value_limits_t::m_max_request_target_length >
			>() );
	m_impl->m_commands.emplace(
			"http.limits.field_name"s,
			std::make_unique<
					http_msg_limits_single_value_handler_t<
							&http_message_value_limits_t::m_max_field_name_length >
			>() );
	m_impl->m_commands.emplace(
			"http.limits.field_value"s,
			std::make_unique<
					http_msg_limits_single_value_handler_t<
							&http_message_value_limits_t::m_max_field_value_length >
			>() );
	m_impl->m_commands.emplace(
			"http.limits.total_headers_size"s,
			std::make_unique<
					http_msg_limits_single_value_handler_t<
							&http_message_value_limits_t::m_max_total_headers_size >
			>() );
	m_impl->m_commands.emplace(
			"http.limits.status_line"s,
			std::make_unique<
					http_msg_limits_single_value_handler_t<
							&http_message_value_limits_t::m_max_status_line_length >
			>() );

	m_impl->m_commands.emplace(
			"acl"s,
			std::make_unique< acl_handler_t >() );
}

config_parser_t::~config_parser_t()
{}

[[nodiscard]]
config_t
config_parser_t::parse( std::string_view content )
{
	config_t result;

	// Counter for processed commands.
	// If it is zero after processing then we've got an empty config and
	// that is an error.
	std::size_t commands_processed{};

	using namespace parse_config_impl;

	line_reader_t line_reader{ content };
	line_reader.for_each_line( [&]( const line_reader_t::line_t & line ) {
			auto [command, rest] = split_line( line.content() );
			const auto handler = m_impl->find_command_handler( command );
			if( handler )
			{
				const auto handling_result = handler->try_handle( rest, result );
				if( const auto failure = std::get_if<failure_t>(&handling_result) )
				{
					throw parser_exception_t{
							fmt::format( "unable to process command {} at line {}: {}",
									command,
									line.number(),
									failure->description() )
						};
				}

				++commands_processed;
			}
			else
				throw parser_exception_t{
						fmt::format( "unknown command {} at line {}",
								command, line.number() )
					};
		} );

	if( !commands_processed )
		throw parser_exception_t{ "Empty config" };

	if( result.m_nameserver_ips.empty() )
		throw parser_exception_t{
			"At least one name server IP should be specified"
		};

	return result;
}

} /* namespace arataga */

