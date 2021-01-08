/*!
 * @file
 * @brief Повторно используемые средства для разбора значений IP-адресов.
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
 * @brief Предикат для easy_parser-а, который распознает разрешенные
 * для использования в IP-адресах символы.
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
 * @brief Продюсер для easy_parser-а, который извлекает разрешенные
 * для использования в IP-адресах символы.
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
 * @brief Продюсер для easy_parser-а, который извлекает последовательность
 * разрешенных для использования в IP-адресах символов.
 *
 * Этот продюсер производит экземпляр std::string.
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
 * @brief Продюсер для easy_parser-а, который извлекает значение IPv4-адреса.
 *
 * Этот продюсер производит экземпляр asio::ip::address_v4.
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
 * @brief Продюсер для easy_parser-а, который извлекает значение IP-адреса.
 *
 * Этот продюсер производит экземпляр asio::ip::address.
 *
 * Сам IP-адрес может быть как IPv4, так и IPv6.
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

