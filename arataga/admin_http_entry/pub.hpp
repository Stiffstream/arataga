/*!
 * @file
 * @brief The public interface of admin HTTP-entry.
 */

#pragma once

#include <arataga/exception.hpp>

#include <asio/ip/address.hpp>

#include <memory>
#include <optional>
#include <string>

namespace arataga::admin_http_entry
{

//
// running_entry_instance_t
//
/*!
 * @brief Interface of an object for stopping the running HTTP-entry.
 */
class running_entry_instance_t
{
public:
	virtual ~running_entry_instance_t();

	//! Sends 'stop' command to HTTP-entry.
	virtual void
	stop() = 0;
};

//
// running_entry_handle_t
//
//! Alias for unique_ptr to running_entry_instance.
using running_entry_handle_t = std::unique_ptr< running_entry_instance_t >;

//
// status_t
//
//! Special type for holding the status-line for a response to a HTTP-request.
class status_t
{
	std::uint16_t m_code;
	const char * m_reason_phrase;

public:
	constexpr explicit status_t(
		std::uint16_t code,
		const char * reason_phrase ) noexcept
		:	m_code{ code }
		,	m_reason_phrase{ reason_phrase }
	{}

	[[nodiscard]]
	constexpr auto
	code() const noexcept { return m_code; }

	[[nodiscard]]
	constexpr auto
	reason_phrase() const noexcept { return m_reason_phrase; }

	[[nodiscard]]
	constexpr bool
	operator<( const status_t & o ) const noexcept
	{
		return this->m_code < o.m_code;
	}

	[[nodiscard]]
	constexpr bool
	operator==( const status_t & o ) const noexcept
	{
		return this->m_code == o.m_code;
	}
};

// Statuses for arataga's replies.
inline constexpr status_t status_ok{
		200u,
		"Ok"
};

inline constexpr status_t status_bad_request{
		400u,
		"Bad Request"
};

inline constexpr status_t status_internal_server_error{
		500u,
		"Internal Server Error"
};

inline constexpr status_t status_config_processor_failure{
		520u,
		"config_processor Failure"
};

inline constexpr status_t status_user_list_processor_failure{
		521u,
		"user_list_processor Failure"
};

//
// replier_t
//
/*!
 * @brief An interface of object for sending a response to an incoming request.
 */
class replier_t
{
public:
	virtual ~replier_t();

	//! Type of holder for parts of the response.
	struct reply_params_t
	{
		//! The value of status-line for the response.
		status_t m_status;
		//! The response's body.
		std::string m_body;
	};

	virtual void
	reply(
		//! The status-line for the response.
		status_t status,
		//! The response's body.
		std::string body ) = 0;

	void
	reply( reply_params_t params )
	{
		this->reply(
				params.m_status,
				std::move(params.m_body) );
	}
};

//
// replier_shptr_t
//
/*!
 * @brief Alias for shared_ptr to replier.
 */
using replier_shptr_t = std::shared_ptr< replier_t >;

namespace debug_requests
{

//! Test request for client's authentification.
struct authentificate_t
{
	asio::ip::address_v4 m_proxy_in_addr;
	std::uint16_t m_proxy_port;

	asio::ip::address_v4 m_user_ip;

	std::optional< std::string > m_username;
	std::optional< std::string > m_password;

	std::string m_target_host;
	std::uint16_t m_target_port;
};

//! Test request for domain name resolving.
struct dns_resolve_t
{
	asio::ip::address_v4 m_proxy_in_addr;
	std::uint16_t m_proxy_port;

	std::string m_target_host;
	std::string m_ip_version;
};

} /* namespace debug_requests */

//
// requests_mailbox_t
//
/*!
 * @brief An interface for sending incoming requests into SObjectizer's
 * part of arataga.
 */
class requests_mailbox_t
{
public:
	virtual ~requests_mailbox_t();

	//! Send a request to apply of new config.
	virtual void
	new_config(
		//! Replier for that request.
		replier_shptr_t replier,
		//! The content of the new config.
		std::string_view content ) = 0;

	//! Send a request to retrieve the current ACL list.
	virtual void
	get_acl_list(
		//! Replier for that request.
		replier_shptr_t replier ) = 0;

	//! Send a request to apply a new user-list.
	virtual void
	new_user_list(
		//! Replier for that request.
		replier_shptr_t replier,
		//! The content of the new user-list.
		std::string_view content ) = 0;

	//! Send a request to retrieve the current stats.
	virtual void
	get_current_stats(
		//! Replier for that request.
		replier_shptr_t replier ) = 0;

	//! Send a test request for user authentification.
	virtual void
	debug_authentificate(
		//! Replier for that request.
		replier_shptr_t replier,
		//! Request's parameters.
		debug_requests::authentificate_t request ) = 0;

	//! Send a test request for domain name resolution.
	virtual void
	debug_dns_resolve(
		//! Replier for that request.
		replier_shptr_t replier,
		//! Request's parameters.
		debug_requests::dns_resolve_t request ) = 0;
};

//
// start_entry
//
/*!
 * @brief Function for launching of the admin HTTP-entry.
 *
 * Returns an actual running_entry_handle_t or throws an exception.
 */
[[nodiscard]]
running_entry_handle_t
start_entry(
	//! IP-address for the admin HTTP-entry.
	asio::ip::address entry_ip,
	//! TCP-port for the admin HTTP-entry.
	std::uint16_t entry_port,
	//! Value of admin-token to be present in all incoming requests.
	//! If there is no admin-token with that value an incoming request
	//! will be rejected.
	std::string admin_token,
	//! The interface for interaction with SObjectizer's part of arataga.
	//! This reference is guaranteed to be valid for the whole lifetime
	//! of the admin HTTP-entry.
	requests_mailbox_t & mailbox );

} /* namespace arataga::admin_http_entry */

