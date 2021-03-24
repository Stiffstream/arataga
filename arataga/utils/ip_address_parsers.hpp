/*!
 * @file
 * @brief Helpers for parsing IP-addresses.
 */

#pragma once

#include <restinio/helpers/easy_parser.hpp>

#include <asio/ip/address.hpp>

namespace arataga::utils::parsers
{

//
// is_ip_address_char_predicate_t
//
/*!
 * @brief A predicate for easy_parser that detects symbols enabled
 * to be used in IP-addresses.
 */
struct is_ip_address_char_predicate_t
{
	[[nodiscard]]
	bool
	operator()( char ch ) const noexcept
	{
		return restinio::easy_parser::impl::is_hexdigit(ch)
				|| '.' == ch
				|| ':' == ch
				;
	}
};

//
// ip_address_char_p
//
/*!
 * @brief A producer for easy_parser that extracts symbols enabled
 * to be used in IP-addresses.
 */
[[nodiscard]]
inline auto
ip_address_char_p() noexcept
{
	return restinio::easy_parser::impl::symbol_producer_template_t<
			is_ip_address_char_predicate_t >{};
}

//
// ip_address_char_seq_p
//
/*!
 * @brief A producer for easy_parser that extracts a sequence of
 * symbols enabled to be used in IP-addresses.
 *
 * Produces an instance of std::string.
 */
[[nodiscard]]
inline auto
ip_address_char_seq_p() noexcept
{
	using namespace restinio::easy_parser;

	return produce< std::string >(
			repeat( 1, N, ip_address_char_p() >> to_container() )
		);
}

//
// ipv4_address_p
//
/*!
 * @brief A procuder for easy_parser that extracts IPv4-address.
 *
 * Produces an instance of asio::ip::address_v4.
 */
[[nodiscard]]
inline auto
ipv4_address_p() noexcept
{
	using namespace restinio::easy_parser;

	using byte_t = asio::ip::address_v4::bytes_type::value_type;
	const auto one_group = non_negative_decimal_number_p< byte_t >();

	return produce< asio::ip::address_v4 >(
		produce< asio::ip::address_v4::bytes_type >(
			repeat( 3u, 3u, one_group >> to_container(), symbol('.') ),
			one_group >> to_container()
		)
		>> convert( []( const auto & arr ) {
				return asio::ip::make_address_v4( arr );
			} )
		>> as_result()
	);
}

//
// ip_address_p
//
/*!
 * @brief A producer for easy_parser that extracts IP-address regardless of
 * its version.
 *
 * Produces an instance of asio::ip::address.
 *
 * Can handle IPv4 and IPv6 addresses.
 */
[[nodiscard]]
inline auto
ip_address_p() noexcept
{
	using namespace restinio::easy_parser;

	const auto try_extract_ip_address =
		[]( const std::string & ip_as_string ) ->
			restinio::expected_t< asio::ip::address, error_reason_t >
		{
			asio::error_code ec;
			auto addr = asio::ip::make_address( ip_as_string, ec );
			if( ec )
				return restinio::make_unexpected(
						error_reason_t::illegal_value_found );

			return { addr };
		};

	return produce< asio::ip::address >(
			produce< std::string >(
				repeat( 1u, N, ip_address_char_p() >> to_container() )
			)
			>> convert( try_extract_ip_address )
			>> as_result()
		);
}

} /* namespace arataga::utils::parsers */

