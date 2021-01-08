/*!
 * @file
 * @brief Публичный интерфейс админстративного HTTP-входа.
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
//! Актуальная реализация интерфейса replier.
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

// Названия точек входа в arataga.
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
 * @brief Фабрика по созданию обработчика, который будет проверять наличие и
 * значение admin-token-а во входящих запросах.
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
				// Можно работать. Заголовок присутствует и
				// имеет корректное значение.
				// Разрешаем передачу запроса следующим обработчикам в цепочке.
				return restinio::request_not_handled();
		}

		// В остальных случаях нужно сразу отвечать отрицательным
		// результатом.
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
 * @brief Фабрика для создания обработчика, который проверяет наличие
 * и содержимое Content-Type для заголовка.
 */
[[nodiscard]]
auto
make_content_type_checker()
{
	return []( const auto & req ) -> restinio::request_handling_status_t
	{
		// Проверять Content-Type нужно только если POST запросы пришли на 
		// /config и /users.
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
				// Ждем содержимое только в формате text/plain, все остальное
				// отвергаем.
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
				// Нельзя брать на обработку запрос, содержимое которого
				// непонятно в каком формате.
				return req->create_response( restinio::status_bad_request() )
						.append_header_date_field()
						.append_body( "No valid Content-Type field found\r\n" )
						.done();
			}
		}

		// Никаких проблем не выявили. Можно разрешать дальнейшую
		// обработку запроса.
		return restinio::request_not_handled();
	};
}

//
// request_processor_t
//
/*!
 * @brief Тип объекта, который будет отвечать за обработку
 * входящих запросов.
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
	//! Почтовый ящик для отсылки запросов в SObjectizer-часть.
	requests_mailbox_t & m_mailbox;

	//! Реакция на запрос с новой конфигурацией.
	[[nodiscard]]
	restinio::request_handling_status_t
	on_new_config(
		restinio::request_handle_t req ) const;

	//! Реакция на запрос списка известных ACL.
	[[nodiscard]]
	restinio::request_handling_status_t
	on_get_acl_list(
		restinio::request_handle_t req ) const;

	//! Реакция на запрос с новым списком пользователей.
	[[nodiscard]]
	restinio::request_handling_status_t
	on_user_list(
		restinio::request_handle_t req ) const;

	//! Реакция на запрос текущей статистики.
	[[nodiscard]]
	restinio::request_handling_status_t
	on_get_current_stats(
		restinio::request_handle_t req ) const;

	//! Реакция на запрос тестовой аутентификации.
	[[nodiscard]]
	restinio::request_handling_status_t
	on_debug_auth(
		restinio::request_handle_t req ) const;

	//! Реакция на запрос тестовой аутентификации.
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
				// Передаем req по значению, чтобы иметь возможность
				// использовать req в секции catch.
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
				// Передаем req по значению, чтобы иметь возможность
				// использовать req в секции catch.
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
	// На данный момент всего три обработчика в цепочке:
	// - проверка admin-token;
	// - проверка content-type для POST-запросов;
	// - прикладная обработка.
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
	//! Дескриптор запущенного RESTinio-сервера.
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
					// Первый обработчик проверяет наличие admin-token-а.
					impl::make_admin_token_checker( std::move(admin_token) ),
					// Следующий обработчик контролирует Content-Type.
					impl::make_content_type_checker(),
					// Следующий обработчик уже делает реальную обработку запроса.
					[handler = std::move(processor)]( auto req ) {
						return handler->on_request( std::move(req) );
					} ),
			// Достаточно одной рабочей нити.
			1 );

	return std::make_unique< impl::actual_running_entry_instance_t >(
			std::move(server) );
}

} /* namespace arataga::admin_http_entry */

