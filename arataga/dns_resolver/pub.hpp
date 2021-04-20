/*!
 * @file
 * @brief The public part of dns_resolver-agent's interface.
 */

#pragma once

#include <arataga/application_context.hpp>
#include <arataga/ip_version.hpp>

#include <arataga/utils/acl_req_id.hpp>
#include <arataga/utils/overloaded.hpp>

#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>

#include <variant>

namespace arataga::dns_resolver
{

//! Type of ID of resolution request.
using resolve_req_id_t = ::arataga::utils::acl_req_id_t;

//
// params_t
//
/*!
 * @brief Initial parameters for dns_resolver-agent.
 */
struct params_t
{
	//! Asio's io_context to be used by dns_resolver.
	/*!
	 * @note
	 * This reference is expected to be valid for the whole lifetime
	 * of dns_resolver-agent.
	 */
	asio::io_context & m_io_ctx;

	//! Dispatcher binder to be used for the creation of children agents.
	so_5::disp_binder_shptr_t m_disp_binder;

	//! Unique name of that agent.
	/*!
	 * Intended to be used for logging.
	 */
	std::string m_name;

	//! Cache cleanup period.
	std::chrono::milliseconds m_cache_cleanup_period;
};

namespace forward
{

//
// successful_resolve_t
//
//!
struct successful_resolve_t
{
	asio::ip::address m_address;
};

//
// failed_resolve_t
//
//!
struct failed_resolve_t
{
	std::string m_error_desc;
};

//
// resolve_result_t
//

using resolve_result_t = std::variant<
	failed_resolve_t,
	successful_resolve_t>;


inline std::ostream &
operator<<( std::ostream & to, const resolve_result_t & result )
{
	std::visit( ::arataga::utils::overloaded
		{
			[&to]( const failed_resolve_t & info )
			{
				to << "(failed: " << info.m_error_desc << ")";
			},
			[&to]( const successful_resolve_t & info )
			{
				to << "(successful: address=" <<
					info.m_address.to_string() << ")";
			}
		},
		result );

	return to;
}

//
// completion_token_t
//
/*!
 * @brief An interface of object that is passed into a resulution
 * request and that has to be returned back in the response.
 *
 * It is expected that this object will simplify the handling
 * of resolution results.
 */
class completion_token_t
{
public:
	virtual ~completion_token_t() = default;

	virtual void
	complete( const resolve_result_t & result ) = 0;
};

//
// completion_token_shptr_t
//
//! An alias for shared_ptr to completion_token.
using completion_token_shptr_t = std::shared_ptr< completion_token_t >;

} // namespace forward

/*!
 * @brief Conversion of string value into ip_version enumeration.
 *
 * @throw std::runtime_error in the case of conversion error.
 */
[[nodiscard]]
inline ip_version_t
from_string(
	//! Value to be converted.
	const std::string & ip )
{
	if( ip == "IPv4" )
		return ip_version_t::ip_v4;
	else if( ip == "IPv6" )
		return ip_version_t::ip_v6;
	else
		throw std::runtime_error(
			"Invalid ip version value: '" + ip +
			"'. Correct values are 'IPv4' and 'IPv6'." );
}

//
// resolve_request_t
//
/*!
 * @brief Domain name resolution request.
 */
struct resolve_request_t final : public so_5::message_t
{
	//! ID of the request.
	resolve_req_id_t m_req_id;

	//! Domain name to be resolved.
	std::string m_name;

	//! IP-version for the response.
	ip_version_t m_ip_version = ip_version_t::ip_v4;

	//! Completion token for that request.
	/*!
	 * @note
	 * Maybe a nullpt.
	 */
	forward::completion_token_shptr_t m_completion_token;

	//! Mbox for the reply.
	so_5::mbox_t m_reply_to;

	resolve_request_t(
		resolve_req_id_t req_id,
		std::string name,
		forward::completion_token_shptr_t completion_token,
		so_5::mbox_t reply_to )
		:	m_req_id{ req_id }
		,	m_name{ std::move(name) }
		,	m_completion_token{ std::move(completion_token) }
		,	m_reply_to{ reply_to }
	{}

	resolve_request_t(
		resolve_req_id_t req_id,
		std::string name,
		ip_version_t ip_version,
		forward::completion_token_shptr_t completion_token,
		so_5::mbox_t reply_to )
		:	m_req_id{ req_id }
		,	m_name{ std::move(name) }
		,	m_ip_version{ std::move(ip_version) }
		,	m_completion_token{ std::move(completion_token) }
		,	m_reply_to{ reply_to }
	{}

	resolve_request_t() = default;
};

//
// resolve_reply_t
//
/*!
 * @brief The reply for resolution request.
 */
struct resolve_reply_t final : public so_5::message_t
{
	using completion_token_t = forward::completion_token_shptr_t;
	using resolve_result_t = forward::resolve_result_t;

	//! ID of the source request.
	resolve_req_id_t m_req_id;

	//! Completion token from the source request.
	/*!
	 * @note
	 * Maybe a nullptr.
	 */
	forward::completion_token_shptr_t m_completion_token;

	//! The result of domain name resolution.
	forward::resolve_result_t m_result;

	resolve_reply_t(
		resolve_req_id_t req_id,
		forward::completion_token_shptr_t completion_token,
		forward::resolve_result_t result )
		:	m_req_id{ req_id }
		,	m_completion_token{ std::move(completion_token) }
		,	m_result{ std::move(result) }
	{}
};

//
// introduce_dns_resolver
//
/*!
 * @brief A factory for the creation of dns_resolver-agent with
 * the binding to the specified dispatcher.
 *
 * Returns a tuple with the ID of a new coop and mbox for interaction
 * with dns_resolver-agent.
 */
[[nodiscard]]
std::tuple< so_5::coop_handle_t, so_5::mbox_t >
introduce_dns_resolver(
	//! SObjectizer Environment to work within.
	so_5::environment_t & env,
	//! The parent coop for a new coop with dns_resolver-agent.
	so_5::coop_handle_t parent_coop,
	//! The dispatcher for a new dns_resolver-agent.
	so_5::disp_binder_shptr_t disp_binder,
	//! The context of the whole application.
	application_context_t app_ctx,
	//! Initial parameters for a new agent.
	params_t params );

} /* namespace arataga::resolver */

