/*!
 * @file
 * @brief Various helpers for working with admin HTTP-entry.
 */

#pragma once

#include <arataga/admin_http_entry/pub.hpp>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <exception>
#include <optional>
#include <string_view>

namespace arataga::admin_http_entry
{

/*!
 * @brief Helper function for synchronous processing of a request
 * from HTTP-entry.
 *
 * This function should be used in the case when the response has
 * to be produced right inside the request processing.
 *
 * The request processing is performed by the lambda-function @a lambda.
 *
 * If @a lambda throws then exceptions are caught and negative
 * response is sent back.
 *
 * @tparam Lambda Type of lambda-function (functor). That lambda-function
 * is called inside envelope_sync_request_handling and it should return
 * the response. That lambda-function should have the following format:
 * @code
 * replier_t::reply_params_t lambda();
 * @endcode
 */
template< typename Lambda >
void
envelope_sync_request_handling(
	//! The description of the context where the processing is initiated.
	//! That description will be used for a negative response in the
	//! case of an exception.
	std::string_view context_description,
	//! The replier for the incoming request.
	replier_t & replier,
	//! Negative status to be used in the case of an exception.
	status_t failure_status,
	//! Lambda-function for actual request processing.
	Lambda && lambda )
{
	std::optional< replier_t::reply_params_t > reply_data;

	// We don't consider exceptions from lambda() as critical.
	try
	{
		reply_data = lambda();
	}
	catch( const std::exception & x )
	{
		reply_data = replier_t::reply_params_t{
				failure_status,
				fmt::format(
						"{} exception caught: {}\r\n",
						context_description,
						x.what() )
		};
	}

	// Don't expect that reply_data can be empty. But do additional check
	// for safety.
	if( reply_data )
		replier.reply( std::move(*reply_data) );
	else
		replier.reply(
				status_internal_server_error,
				fmt::format( "{} doesn't provide "
						"a description of request processing result\r\n",
						context_description ) );
}

/*!
 * @brief Helper function for asynchronous processing of incoming requests.
 *
 * This function should be used when the response can't be created
 * right inside the request handler. In that case the response will
 * be made and sent back to HTTP-entry some time after the return
 * from envelope_async_request_handling.
 *
 * The request processing is performed by the lambda-function @a lambda.
 *
 * If @a lambda throws then exceptions are caught and negative
 * response is sent back.
 *
 * @tparam Lambda Type of lambda-function (functor). That lambda-function
 * is called inside envelope_async_request_handling. That lambda-function
 * should have the following format:
 * @code
 * void lambda();
 * @endcode
 */
template< typename Lambda >
void
envelope_async_request_handling(
	//! The description of the context where the processing is initiated.
	//! That description will be used for a negative response in the
	//! case of an exception.
	std::string_view context_description,
	//! The replier for the incoming request.
	replier_t & replier,
	//! Negative status to be used in the case of an exception.
	status_t failure_status,
	//! Lambda-function for actual request processing.
	Lambda && lambda )
{
	std::optional< replier_t::reply_params_t > reply_data;

	// We don't consider exceptions from lambda() as critical.
	try
	{
		lambda();
	}
	catch( const std::exception & x )
	{
		reply_data = replier_t::reply_params_t{
				failure_status,
				fmt::format(
						"{} exception caught: {}\r\n",
						context_description,
						x.what() )
		};
	}

	if( reply_data )
		replier.reply( std::move(*reply_data) );
}

} /* namespace arataga::admin_http_entry */

