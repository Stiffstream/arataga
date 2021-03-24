/*!
 * @file
 * @brief The public interface of admin HTTP-entry.
 */

#include <arataga/admin_http_entry/pub.hpp>

#include <restinio/sync_chain/fixed_size.hpp>
#include <restinio/all.hpp>

#include <restinio/helpers/http_field_parsers/content-type.hpp>
#include <restinio/helpers/http_field_parsers/try_parse_field.hpp>

#include <stdexcept>

namespace arataga::admin_http_entry
{

//
// running_entry_instance_t
//
running_entry_instance_t::~running_entry_instance_t()
{}

//
// replier_t
//
replier_t::~replier_t()
{}

//
// requests_mailbox_t
//
requests_mailbox_t::~requests_mailbox_t()
{}

namespace impl
{

//
// actual_replier_t
//
//! The actual implementation of replier interface.
class actual_replier_t final : public replier_t
{
public:
	actual_replier_t( restinio::request_handle_t req )
		:	m_request{ std::move(req) }
	{}

	void
	reply(
		status_t status,
		std::string body ) override
	{
		m_request->create_response(
					restinio::http_status_line_t{
							restinio::http_status_code_t{status.code()},
							std::string{status.reason_phrase()}
					}
				)
				.append_header_date_field()
				.append_header(
						restinio::http_field::content_type, "text/plain" )
				.append_body( std::move(body) )
				.done();
	}

private:
	const restinio::request_handle_t m_request;
};

// Names of entry-points.
constexpr std::string_view entry_point_config{ "/config" };
constexpr std::string_view entry_point_acls{ "/acls" };
constexpr std::string_view entry_point_users{ "/users" };
constexpr std::string_view entry_point_stats{ "/stats" };
constexpr std::string_view entry_point_debug_auth{ "/debug/auth" };
constexpr std::string_view entry_point_debug_dns_resolve{ "/debug/dns-resolve" };

//
// make_admin_token_checker
//
/*!
 * @brief A factory for handler that checks the presence and the value
 * of admin-token in incoming requests.
 */
[[nodiscard]]
auto
make_admin_token_checker(
	std::string admin_token )
{
	return [token = std::move(admin_token)]( const auto & req ) ->
		restinio::request_handling_status_t
	{
		const auto admin_header_value = req->header().opt_value_of(
				"Arataga-Admin-Token" );
		if( admin_header_value )
		{
			if( token == *admin_header_value )
				// There is the required field and it has the right value.
				// We can go further. Allow to work to the next worker.
				return restinio::request_not_handled();
		}

		// In all other cases the negative response has to be sent.
		return req->create_response( restinio::status_forbidden() )
				.append_header_date_field()
				.append_body( "No valid admin credentials supplied\r\n" )
				.done();
	};
}

//
// make_content_type_checker
//
/*!
 * @brief A factory for handler that checks the presence and the
 * value of Content-Type for headers.
 */
[[nodiscard]]
auto
make_content_type_checker()
{
	return []( const auto & req ) -> restinio::request_handling_status_t
	{
		// The check is necessary only if it is POST request for
		// /config and /users entries.
		if( restinio::http_method_post() == req->header().method() &&
				(req->header().path() == entry_point_config ||
				req->header().path() == entry_point_users) )
		{
			using namespace restinio::http_field_parsers;

			const auto parse_result = try_parse_field< content_type_value_t >(
					*req, restinio::http_field::content_type );
			if( const auto * ct_val = std::get_if< content_type_value_t >(
					&parse_result ) )
			{
				// Wait the content only in text/plain format. Reject all
				// other content types.
				if( !("text" == ct_val->media_type.type &&
						"plain" == ct_val->media_type.subtype) )
				{
					return req->create_response( restinio::status_bad_request() )
							.append_header_date_field()
							.append_body( "Content is expected in "
									"text/plain format\r\n" )
							.done();
				}
			}
			else
			{
				// We can't process the request with unknown content-type.
				return req->create_response( restinio::status_bad_request() )
						.append_header_date_field()
						.append_body( "No valid Content-Type field found\r\n" )
						.done();
			}
		}

		// There is no problem. Go to the next handler.
		return restinio::request_not_handled();
	};
}

//
// request_processor_t
//
/*!
 * @brief Type of object for handling incoming requests.
 */
class request_processor_t
{
public:
	request_processor_t(
		requests_mailbox_t & mailbox );

	[[nodiscard]]
	restinio::request_handling_status_t
	on_request( restinio::request_handle_t req );

private:
	//! Mailbox for sending requests to SObjectizer's part of arataga.
	requests_mailbox_t & m_mailbox;

	//! The handler for a request with a new config.
	[[nodiscard]]
	restinio::request_handling_status_t
	on_new_config(
		restinio::request_handle_t req ) const;

	//! The handler for a request for retrieving of ACL list.
	[[nodiscard]]
	restinio::request_handling_status_t
	on_get_acl_list(
		restinio::request_handle_t req ) const;

	//! The handler for a request with a new user-list.
	[[nodiscard]]
	restinio::request_handling_status_t
	on_user_list(
		restinio::request_handle_t req ) const;

	//! The handler for a request for retrieving the current stats.
	[[nodiscard]]
	restinio::request_handling_status_t
	on_get_current_stats(
		restinio::request_handle_t req ) const;

	//! The handler for a request with test authentification.
	[[nodiscard]]
	restinio::request_handling_status_t
	on_debug_auth(
		restinio::request_handle_t req ) const;

	//! The handler for a request with test domain name resolution.
	[[nodiscard]]
	restinio::request_handling_status_t
	on_debug_dns_resolve(
		restinio::request_handle_t req ) const;
};

request_processor_t::request_processor_t(
	requests_mailbox_t & mailbox )
	:	m_mailbox{ mailbox }
{}

restinio::request_handling_status_t
request_processor_t::on_request( restinio::request_handle_t req )
{
	if( restinio::http_method_post() == req->header().method() &&
			req->header().path() == entry_point_config )
	{
		return on_new_config( std::move(req) );
	}

	if( restinio::http_method_get() == req->header().method() &&
			req->header().path() == entry_point_acls )
	{
		return on_get_acl_list( std::move(req) );
	}

	if( restinio::http_method_post() == req->header().method() &&
			req->header().path() == entry_point_users )
	{
		return on_user_list( std::move(req) );
	}

	if( restinio::http_method_get() == req->header().method() &&
			req->header().path() == entry_point_stats )
	{
		return on_get_current_stats( std::move(req) );
	}

	if( restinio::http_method_get() == req->header().method() &&
			req->header().path() == entry_point_debug_auth )
	{
		return on_debug_auth( std::move(req) );
	}

	if( restinio::http_method_get() == req->header().method() &&
			req->header().path() == entry_point_debug_dns_resolve )
	{
		return on_debug_dns_resolve( std::move(req) );
	}

	return req->create_response( restinio::status_not_implemented() )
			.append_header_date_field()
			.done();
}

restinio::request_handling_status_t
request_processor_t::on_new_config(
	restinio::request_handle_t req ) const
{
	std::string_view content{ req->body() };
	m_mailbox.new_config(
			std::make_shared< actual_replier_t >( std::move(req) ),
			content );

	return restinio::request_accepted();
}

restinio::request_handling_status_t
request_processor_t::on_get_acl_list(
	restinio::request_handle_t req ) const
{
	m_mailbox.get_acl_list(
			std::make_shared< actual_replier_t >( std::move(req) ) );

	return restinio::request_accepted();
}

restinio::request_handling_status_t
request_processor_t::on_user_list(
	restinio::request_handle_t req ) const
{
	std::string_view content{ req->body() };
	m_mailbox.new_user_list(
			std::make_shared< actual_replier_t >( std::move(req) ),
			content );

	return restinio::request_accepted();
}

[[nodiscard]]
restinio::request_handling_status_t
request_processor_t::on_get_current_stats(
	restinio::request_handle_t req ) const
{
	m_mailbox.get_current_stats(
			std::make_shared< actual_replier_t >( std::move(req) ) );

	return restinio::request_accepted();
}

restinio::request_handling_status_t
request_processor_t::on_debug_auth(
	restinio::request_handle_t req ) const
{
	try
	{
		const auto qp = restinio::parse_query<
					restinio::parse_query_traits::javascript_compatible >(
				req->header().query() );

		debug_requests::authentificate_t request_params;

		request_params.m_proxy_in_addr = asio::ip::make_address_v4(
				qp[ "proxy-in-addr" ] );
		request_params.m_proxy_port = restinio::cast_to< std::uint16_t >(
				qp[ "proxy-port" ] );
		request_params.m_user_ip = asio::ip::make_address_v4(
				qp[ "user-ip" ] );
		request_params.m_target_host = restinio::cast_to< std::string >(
				qp[ "target-host" ] );
		request_params.m_target_port = restinio::cast_to< std::uint16_t >(
				qp[ "target-port" ] );

		if( qp.has( "username" ) )
		{
			request_params.m_username = restinio::cast_to< std::string >(
					qp[ "username" ] );
			if( qp.has( "password" ) )
				request_params.m_password = restinio::cast_to< std::string >(
						qp[ "password" ] );
		}

		m_mailbox.debug_authentificate(
				// NOTE: `req` is passed by value.
				// It allows us to use `req` in catch block.
				std::make_shared< actual_replier_t >( req ),
				std::move(request_params) );
	}
	catch( const std::exception & x )
	{
		req->create_response( restinio::status_bad_request() )
			.append_header_date_field()
			.append_body(
					fmt::format( "Error during parsing request parameters: {}\r\n",
							x.what() ) )
			.done();
	}

	return restinio::request_accepted();
}

restinio::request_handling_status_t
request_processor_t::on_debug_dns_resolve(
	restinio::request_handle_t req ) const
{
	try
	{
		const auto qp = restinio::parse_query<
			restinio::parse_query_traits::javascript_compatible >(
				req->header().query() );

		debug_requests::dns_resolve_t request_params;

		request_params.m_proxy_in_addr = asio::ip::make_address_v4(
				qp[ "proxy-in-addr" ] );
		request_params.m_proxy_port = restinio::cast_to< std::uint16_t >(
				qp[ "proxy-port" ] );
		request_params.m_target_host = restinio::cast_to< std::string >(
				qp[ "target-host" ] );

		if( qp.has( "ip-version" ) )
			request_params.m_ip_version = restinio::cast_to< std::string >(
				qp[ "ip-version" ] );

		m_mailbox.debug_dns_resolve(
				// NOTE: `req` is passed by value.
				// It allows us to use `req` in catch block.
				std::make_shared< actual_replier_t >( req ),
				std::move(request_params) );
	}
	catch( const std::exception & x )
	{
		req->create_response( restinio::status_bad_request() )
			.append_header_date_field()
			.append_body(
					fmt::format( "Error during parsing request parameters: {}\r\n",
							x.what() ) )
			.done();
	}

	return restinio::request_accepted();
}

//
// server_traits_t
//
struct server_traits_t : public restinio::default_traits_t 
{
	// There are only three handlers in the chain:
	// - checks for admin-token;
	// - checks for content-type for POST-requests;
	// - actual handling.
	using request_handler_t = restinio::sync_chain::fixed_size_chain_t<3>;
};

//
// actual_running_entry_instance_t
//
class actual_running_entry_instance_t
	:	public running_entry_instance_t
{
public:
	using server_handle_t =
			restinio::running_server_handle_t< server_traits_t >;

	actual_running_entry_instance_t(
		server_handle_t h_server )
		:	m_server{ std::move(h_server) }
	{}

	void
	stop() override
	{
		m_server->stop();
	}

private:
	//! A handle of the running RESTinio-server.
	server_handle_t m_server;
};

} /* namespace impl */

//
// start_entry
//
[[nodiscard]]
running_entry_handle_t
start_entry(
	asio::ip::address entry_ip,
	std::uint16_t entry_port,
	std::string admin_token,
	requests_mailbox_t & mailbox )
{
	auto processor = std::make_shared< impl::request_processor_t >(
			mailbox );

	auto server = restinio::run_async(
			restinio::own_io_context(),
			restinio::server_settings_t< impl::server_traits_t >{}
				.address( entry_ip )
				.port( entry_port )
				.request_handler(
					// The first handler checks admin-token.
					impl::make_admin_token_checker( std::move(admin_token) ),
					// The next handler checks Content-Type for POST-requests.
					impl::make_content_type_checker(),
					// The next handler does the actual processing.
					[handler = std::move(processor)]( auto req ) {
						return handler->on_request( std::move(req) );
					} ),
			// Just one worker thread is enough.
			1 );

	return std::make_unique< impl::actual_running_entry_instance_t >(
			std::move(server) );
}

} /* namespace arataga::admin_http_entry */

