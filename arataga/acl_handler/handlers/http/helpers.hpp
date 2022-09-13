/*!
 * @file
 * @brief Various helpers for HTTP connection_handlers.
 */

#pragma once

#include <arataga/nothrow_block/macros.hpp>

#include <nodejs/http_parser/http_parser.h>

#include <utility>

namespace arataga::acl_handler
{

namespace handlers::http
{

namespace helpers
{

template<
	typename Handler,
	typename... Args >
[[nodiscard]]
int
wrap_http_parser_callback(
	http_parser * parser,
	int (Handler::*callback)( Args... ),
	Args ...args ) noexcept
{
	auto * handler = reinterpret_cast<Handler *>(parser->data);

	ARATAGA_NOTHROW_BLOCK_BEGIN()
		return (handler->*callback)( std::forward<Args>(args)... );
	ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_IGNORE)

	return -1;
}

template< typename T >
struct http_parser_callback_kind_detector;

template< typename Handler >
struct http_parser_callback_kind_detector<
	int (Handler::*)() >
{
	static constexpr bool with_data = false;
};

template< typename Handler >
struct http_parser_callback_kind_detector<
	int (Handler::*)( const char *, std::size_t ) >
{
	static constexpr bool with_data = true;
};

template< auto Callback >
[[nodiscard]]
auto
make_http_parser_callback() noexcept
{
	using detector = http_parser_callback_kind_detector< decltype(Callback) >;

	if constexpr( detector::with_data )
		return []( http_parser * parser, const char * data, std::size_t size )
			{
				return wrap_http_parser_callback( parser, Callback, data, size );
			};
	else
		return []( http_parser * parser )
			{
				return wrap_http_parser_callback( parser, Callback );
			};
}

[[nodiscard]]
constexpr bool
is_bodyless_method( http_method method ) noexcept
{
	return ( HTTP_CONNECT == method
			|| HTTP_HEAD == method
			|| HTTP_TRACE == method
			);
}

} /* namespace helpers */

} /* namespace arataga::acl_handler */

} /* namespace handlers::http */

