/*!
 * @file
 * @brief The public part of authentificator-agent interface.
 */

#pragma once

#include <arataga/application_context.hpp>

#include <arataga/user_list_auth_data.hpp>

#include <arataga/utils/acl_req_id.hpp>
#include <arataga/utils/overloaded.hpp>

#include <cstdint>
#include <optional>
#include <variant>

namespace arataga::authentificator
{

// Necessary data types.

//! Type of ID for authentification request.
using auth_req_id_t = ::arataga::utils::acl_req_id_t;

//! Type of IP-address for ACL and clients.
/*!
 * @note
 * Only IPv4 addresses are supported at the moment.
 */
using ipv4_address_t = ::arataga::user_list_auth::ipv4_address_t;

//! Type of IP-port number.
using ip_port_t = ::arataga::user_list_auth::ip_port_t;

//! Type of ID for a user.
using user_id_t = ::arataga::user_list_auth::user_id_t;

//! Type for holding a limit for a single domain.
using one_domain_limit_t = ::arataga::user_list_auth::site_limits_data_t::one_limit_t;

//
// params_t
//
/*!
 * @brief Initial params for authentificator-agent.
 */
struct params_t
{
	//! Unique name of the agent to be used in log messages.
	std::string m_name;
};

//
// introduce_authentificator
//
/*!
 * @brief A factory for the creation of a new authentificator-agent
 * and the registration of it with binding to the specified dispatcher.
 *
 * A tuple with ID of new coop and mbox for interaction with
 * the new authentificator-agent is returned.
 */
[[nodiscard]]
std::tuple< so_5::coop_handle_t, so_5::mbox_t >
introduce_authentificator(
	//! SObjectizer Environment to work within.
	so_5::environment_t & env,
	//! The parent coop for a new agent.
	so_5::coop_handle_t parent_coop,
	//! The dispatcher for a new agent.
	so_5::disp_binder_shptr_t disp_binder,
	//! The context of the whole application.
	application_context_t app_ctx,
	//! Initial parameters for a new agent.
	params_t params );

//
// failure_reason_t
//
//! The reason of failed authentification/authorization.
enum class failure_reason_t
{
	//! The user isn't found in a list of allowed users for the ACL.
	unknown_user,

	//! The user can connect to the ACL but has no rights to access
	//! the target host.
	target_blocked,

	//! The authentification timed out.
	auth_operation_timedout,
};

//! A helper function for getting a string representation of
//! failure_reason value.
[[nodiscard]]
std::string_view
to_string_view( failure_reason_t reason ) noexcept;

//
// failed_auth_t
//
//! Description of authentification failure.
struct failed_auth_t
{
	//! Why the authentification/authorization failed.
	failure_reason_t m_reason;
};

//
// successful_auth_t
//
//! The result of a successful authentification/authorization.
struct successful_auth_t
{
	//! ID of the user.
	user_id_t m_user_id;

	//! Personal limits for that user.
	bandlim_config_t m_user_bandlims;

	//! Personal limit for the target host for that user.
	std::optional< one_domain_limit_t > m_domain_limits;
};

//
// auth_result_t
//
//! Type of authentification result.
using auth_result_t = std::variant< failed_auth_t, successful_auth_t >;

// NOTE: for logging and debugging purposes only.
inline std::ostream &
operator<<( std::ostream & to, const auth_result_t & v )
{
	std::visit( ::arataga::utils::overloaded{
			[&to]( const failed_auth_t & info ) {
				to << "(failed: " << to_string_view(info.m_reason) << ')';
			},
			[&to]( const successful_auth_t & info ) {
				to << "(successful: user_id=" << info.m_user_id << ", ("
						<< info.m_user_bandlims << ")";
				if( info.m_domain_limits )
				{
					to << ", (" << info.m_domain_limits->m_domain << ": "
						<< info.m_domain_limits->m_bandlims << ")";
				}
				to << ")";
			}
		},
		v );
		
	return to;
}

//
// completion_token_t
//
/*!
 * @brief Interface of object that is passed in an authentification
 * request and should be returned back in the response.
 *
 * It is expected that this object will simplify the handling
 * of authentification results.
 */
class completion_token_t
{
public:
	virtual ~completion_token_t();

	virtual void
	complete( const auth_result_t & result ) = 0;
};

//
// completion_token_shptr_t
//
//! An alias for shared_ptr to completion_token.
using completion_token_shptr_t = std::shared_ptr< completion_token_t >;

//
// auth_request_t
//
/*!
 * @brief Authentification request.
 */
struct auth_request_t final : public so_5::message_t
{
	//! ID of the request.
	auth_req_id_t m_req_id;
	//! Mbox for the reply with the result.
	so_5::mbox_t m_reply_to;

	//! Completion token for the request.
	/*!
	 * @note
	 * Maybe a nullptr.
	 */
	completion_token_shptr_t m_completion_token;

	//! IP address of ACL to that client is connected.
	ipv4_address_t m_proxy_in_addr;
	//! TCP-port of ACL to that client is connected.
	ip_port_t m_proxy_port;

	//! IP address of the client.
	ipv4_address_t m_user_ip;

	//! Name of the user.
	std::optional< std::string > m_username;
	//! Password of the user.
	std::optional< std::string > m_password;

	//! The client's target.
	/*!
	 * This is the domain name.
	 */
	std::string m_target_host;
	//! TCP-port on the target host where the client want to connect.
	ip_port_t m_target_port;
};

//
// auth_reply_t
//
/*!
 * @brief Response to an authentification request.
 */
struct auth_reply_t final : public so_5::message_t
{
	//! ID of the request.
	auth_req_id_t m_req_id;

	//! Completion token from the request.
	/*!
	 * @note
	 * Maybe a nullptr.
	 */
	completion_token_shptr_t m_completion_token;

	//! The result of the authentification/authorization.
	auth_result_t m_result;

	auth_reply_t(
		auth_req_id_t req_id,
		completion_token_shptr_t completion_token,
		auth_result_t result )
		:	m_req_id{ req_id }
		,	m_completion_token{ std::move(completion_token) }
		,	m_result{ std::move(result) }
	{}
};

} /* namespace arataga::authentificator */

