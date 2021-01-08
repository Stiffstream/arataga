/*!
 * @file
 * @brief Реализация authentification_handler-а.
 */

#include <arataga/acl_handler/handlers/http/basics.hpp>
#include <arataga/acl_handler/handlers/http/factories.hpp>
#include <arataga/acl_handler/handlers/http/helpers.hpp>
#include <arataga/acl_handler/handlers/http/responses.hpp>

#include <arataga/utils/overloaded.hpp>

#include <restinio/helpers/http_field_parsers/authorization.hpp>
#include <restinio/helpers/http_field_parsers/basic_auth.hpp>
#include <restinio/helpers/http_field_parsers/host.hpp>

namespace arataga::acl_handler
{

namespace handlers::http
{

//
// authentification_handler_t
//
/*!
 * @brief Обработчик соединения, который производит аутентификацию клиента.
 */
class authentification_handler_t final : public basic_http_handler_t
{
	//! Результат успешного извлечения username/password из
	//! заголовков HTTP-запроса.
	struct username_password_t
	{
		std::string m_username;
		std::string m_password;
	};

	//! Структура для случая, когда username/password вообще не были
	//! заданы.
	struct no_username_password_provided_t {};

	//! Структура для случая, когда username/password не удалось
	//! извлечь из-за какой-то ошибки.
	struct username_password_extraction_failure_t
	{
		//! Описание возникшей ошибки.
		std::string m_description;
	};

	//! Общий результат извлечения username/password из параметров запроса.
	using username_password_extraction_result_t = std::variant<
			username_password_t,
			no_username_password_provided_t,
			username_password_extraction_failure_t
		>;

	//! Результат успешного извлечения имени целевого узла и номера порта.
	struct target_host_and_port_t
	{
		std::string m_host;
		std::uint16_t m_port;
	};

	//! Результат неудачного извлечения имени целевого узла и номера порта.
	struct target_host_and_port_extraction_failure_t
	{
		//! Описание возникшей ошибки.
		std::string m_description;
	};

	//! Общий результат извлечения имени целевого узна и номера порта
	//! из параметров запроса.
	using target_host_and_port_extraction_result_t = std::variant<
			target_host_and_port_t,
			target_host_and_port_extraction_failure_t
		>;

	//! Результат успешного преобразования request-target.
	struct update_request_target_success_t {};

	//! Результат неудачного преобразования request-target.
	struct update_request_target_failure_t
	{
		//! Описание возникшей ошибки.
		std::string m_description;
	};

	//! Общий результат преобразования request-target.
	using update_request_target_result_t = std::variant<
			update_request_target_success_t,
			update_request_target_failure_t
		>;

	//! Состояние разбора исходного запроса.
	http_handling_state_unique_ptr_t m_request_state;

	//! Дополнительная информация по исходному запросу.
	/*!
	 * В результате успешного анализа request-target и заголовка Host
	 * сюда будет сохранен актуальный target-host и target-port.
	 */
	request_info_t m_request_info;

	//! Время, когда аутентификация началась.
	std::chrono::steady_clock::time_point m_created_at;

public:
	authentification_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		http_handling_state_unique_ptr_t request_state,
		request_info_t request_info )
		:	basic_http_handler_t{ std::move(ctx), id, std::move(connection) }
		,	m_request_state{ std::move(request_state) }
		,	m_request_info{ std::move(request_info) }
		,	m_created_at{ std::chrono::steady_clock::now() }
	{
	}

protected:
	void
	on_start_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
			delete_protector,
			[this]( delete_protector_t delete_protector, can_throw_t can_throw )
			{
				// Нужно определить имя пользователя и пароль, если
				// они заданы.
				auto username_password_extraction_result =
						try_extract_username_and_password( can_throw );
				// В случае ошибки продолжать нет смысла.
				if( auto * err = std::get_if<username_password_extraction_failure_t>(
						&username_password_extraction_result); err )
				{
					::arataga::logging::wrap_logging(
							proxy_logging_mode,
							spdlog::level::err,
							[this, can_throw, err]( auto level )
							{
								log_message_for_connection(
										can_throw,
										level,
										fmt::format(
												"username/password extraction failure: {}",
												err->m_description ) );
							} );

					send_negative_response_then_close_connection(
							delete_protector,
							can_throw,
							remove_reason_t::protocol_error,
							response_bad_request_auth_params_extraction_failure );

					return;
				}

				// Нужно определить целевой узел и номер порта на нем.
				auto target_host_and_port_extraction_result =
						try_extract_target_host_and_port( can_throw );
				if( auto * err = std::get_if<target_host_and_port_extraction_failure_t>(
						&target_host_and_port_extraction_result); err )
				{
					::arataga::logging::wrap_logging(
							proxy_logging_mode,
							spdlog::level::err,
							[this, can_throw, err]( auto level )
							{
								log_message_for_connection(
										can_throw,
										level,
										fmt::format(
												"target-host+port extraction failure: {}",
												err->m_description ) );
							} );

					send_negative_response_then_close_connection(
							delete_protector,
							can_throw,
							remove_reason_t::protocol_error,
							response_bad_request_target_host_extraction_failure );

					return;
				}

				// Нужно преобразовать request-target из absolute-form
				// в origin-form, если request-target был задан в absolute-form.
				auto update_request_target_result =
						try_update_request_target( can_throw );
				if( auto * err = std::get_if<update_request_target_failure_t>(
						&update_request_target_result); err )
				{
					::arataga::logging::wrap_logging(
							proxy_logging_mode,
							spdlog::level::err,
							[this, can_throw, err]( auto level )
							{
								log_message_for_connection(
										can_throw,
										level,
										fmt::format(
												"update request-target failure: {}",
												err->m_description ) );
							} );

					send_negative_response_then_close_connection(
							delete_protector,
							can_throw,
							remove_reason_t::protocol_error,
							response_bad_request_invalid_request_target );

					return;
				}


				// Осталось только инциировать саму аутентификацию.
				initiate_authentification(
						can_throw,
						username_password_extraction_result,
						target_host_and_port_extraction_result );
			} );
	}

	void
	on_timer_impl( delete_protector_t delete_protector ) override
	{
		if( std::chrono::steady_clock::now() >= m_created_at +
				context().config().authentification_timeout() )
		{
			wrap_action_and_handle_exceptions(
				delete_protector,
				[this]( delete_protector_t delete_protector, can_throw_t can_throw )
				{
					::arataga::logging::wrap_logging(
							proxy_logging_mode,
							spdlog::level::warn,
							[this, can_throw]( auto level )
							{
								log_message_for_connection(
										can_throw,
										level,
										"authentification timed out" );
							} );

					// Осталось только отослать ответ и закрыть соединение.
					send_negative_response_then_close_connection(
							delete_protector,
							can_throw,
							remove_reason_t::current_operation_timed_out,
							response_proxy_auth_required_auth_timeout );
				} );
		}
	}

public:
	std::string_view
	name() const noexcept override
	{
		return "http-authenitification-handler";
	}

private:
	[[nodiscard]]
	username_password_extraction_result_t
	try_extract_username_and_password(
		can_throw_t /*can_throw*/ )
	{
		auto opt_proxy_auth_value = m_request_info.m_headers.opt_value_of(
				restinio::http_field_t::proxy_authorization );
		if( !opt_proxy_auth_value )
			return no_username_password_provided_t{};

		using namespace restinio::http_field_parsers;
		const auto auth_value_result = authorization_value_t::try_parse(
				*opt_proxy_auth_value );
		if( !auth_value_result )
			return username_password_extraction_failure_t{
					make_error_description(
							auth_value_result.error(),
							*opt_proxy_auth_value )
			};

		auto & auth_value = *auth_value_result;
		if( "basic" != auth_value.auth_scheme )
			return username_password_extraction_failure_t{
					fmt::format( "unsupported auth-scheme: {}",
							auth_value.auth_scheme )
			};

		auto basic_auth_result = basic_auth::try_extract_params(
				auth_value );
		if( !basic_auth_result )
			return username_password_extraction_failure_t{
					fmt::format( "basic-auth param extraction failed: {}",
							static_cast<int>(basic_auth_result.error()) )
			};

		// Заголовок Proxy-Authorization больше не нужен и должен
		// быть удален.
		m_request_info.m_headers.remove_all_of(
				restinio::http_field_t::proxy_authorization );

		auto & basic_auth = *basic_auth_result;
		return username_password_t{
				std::move(basic_auth.username),
				std::move(basic_auth.password)
		};
	}

	[[nodiscard]]
	target_host_and_port_extraction_result_t
	try_extract_target_host_and_port( can_throw_t can_throw )
	{
		auto extraction_result =
				try_extract_target_host_and_port_from_request_target( can_throw );

		if( std::holds_alternative<target_host_and_port_extraction_failure_t>(
				extraction_result ) )
		{
			extraction_result =
					try_extract_target_host_and_port_from_host_field( can_throw );
		}

		// После извлечения значения заголовок Host должен быть удален.
		m_request_info.m_headers.remove_all_of( restinio::http_field_t::host );

		return extraction_result;
	}

	[[nodiscard]]
	target_host_and_port_extraction_result_t
	try_extract_target_host_and_port_from_request_target(
		can_throw_t /*can_throw*/ )
	{
		// Сперва попытаемся разобрать URL на части.
		http_parser_url parser_url;
		http_parser_url_init( &parser_url );

		const auto & value_to_process = m_request_info.m_request_target;

		const auto parse_url_result = http_parser_parse_url(
				value_to_process.data(),
				value_to_process.size(),
				HTTP_CONNECT == m_request_state->m_parser.method,
				&parser_url );
		if( parse_url_result )
			return target_host_and_port_extraction_failure_t{
					fmt::format( "unable to parse request-target, "
							"http_parser_parse_url result: {}",
							parse_url_result )
			};

		const auto is_component_present = [&]( unsigned int component ) -> bool
			{
				return parser_url.field_set & (1u << component);
			};

		const auto try_extract_url_component =
			[&]( unsigned int component ) -> std::string_view
			{
				std::string_view result;
				if( is_component_present(component) )
					result = std::string_view{
							value_to_process.data() +
									parser_url.field_data[component].off,
							parser_url.field_data[component].len
					};
				return result;
			};

		const auto schema_sv = try_extract_url_component( UF_SCHEMA );
		const auto host_sv = try_extract_url_component( UF_HOST );

		std::optional< std::uint16_t > opt_port{ 80u };
		if( is_component_present( UF_PORT ) ) 
			opt_port = parser_url.port;

		if( !host_sv.empty() && opt_port )
			// У нас уже есть результат.
			return target_host_and_port_t{
					std::string{ host_sv },
					*opt_port
			};

		// Если есть schema и host, то можно попробовать определить
		// port самостоятельно.
		if( !schema_sv.empty() && !host_sv.empty() )
		{
			if( "http" == schema_sv )
				return target_host_and_port_t{
						std::string{ host_sv },
						80u
				};
			else if( "https" == schema_sv )
				return target_host_and_port_t{
						std::string{ host_sv },
						443u
				};
			else
				// Схема, которую мы не поддерживаем.
				return target_host_and_port_extraction_failure_t{
						fmt::format( "unsupported schema in request-target: {}",
								schema_sv )
				};
		}

		// Не смогли извлечь target-host и port.
		return target_host_and_port_extraction_failure_t{
				fmt::format( "no target-host and port in request-target" )
		};
	}

	[[nodiscard]]
	target_host_and_port_extraction_result_t
	try_extract_target_host_and_port_from_host_field(
		can_throw_t /*can_throw*/ )
	{
		// Если количество заголовков Host больше 1, то запрос
		// должен быть отвергнут. Поэтому бежим по всем значениям
		// Host и считаем их количество.
		std::optional< std::string_view > opt_host;
		std::size_t host_occurrences{ 0u };

		m_request_info.m_headers.for_each_value_of(
				restinio::http_field_t::host,
				[&]( std::string_view value )
				{
					++host_occurrences;
					if( 1u == host_occurrences )
					{
						opt_host = value;
					}

					return restinio::http_header_fields_t::continue_enumeration();
				} );

		if( 0u == host_occurrences )
			return target_host_and_port_extraction_failure_t{
					"no Host http-field"
			};
		else if( 1u != host_occurrences )
			return target_host_and_port_extraction_failure_t{
					fmt::format( "too many Host http-fields: {}",
							host_occurrences )
			};

		// Осталось разобрать значение.
		// Используем парсер значения Host из RESTinio потому, что, как
		// оказалось, http_parser_parse_url не может справится со
		// значениями вида "localhost:9090".
		using namespace restinio::http_field_parsers;

		auto parse_result = raw_host_value_t::try_parse( opt_host.value() );
		if( !parse_result )
			return target_host_and_port_extraction_failure_t{
					fmt::format( "unable to parse Host http-field: {}",
							make_error_description(
									parse_result.error(),
									opt_host.value() ) )
			};

		std::string target_host = std::visit(
				::arataga::utils::overloaded{
					[]( raw_host_value_t::reg_name_t & n ) -> std::string
					{
						return std::move(n.v);
					},
					[]( raw_host_value_t::ipv4_address_t & n ) -> std::string
					{
						return std::move(n.v);
					},
					[]( raw_host_value_t::ipv6_address_t & n ) -> std::string
					{
						return std::move(n.v);
					}
				},
				parse_result->host );

		return target_host_and_port_t{
				std::move(target_host),
				parse_result->port ? *(parse_result->port) : std::uint16_t{80u}
		};
	}

	[[nodiscard]]
	update_request_target_result_t
	try_update_request_target(
		can_throw_t /*can_throw*/ )
	{
		// Значение request-target нужно забрать в отдельный объект,
		// т.к. на его содержимое затем нужно будет ссылаться.
		std::string value_to_process{
				std::move(m_request_info.m_request_target)
			};

		// Сперва попытаемся разобрать URL на части.
		http_parser_url parser_url;
		http_parser_url_init( &parser_url );

		const auto parse_url_result = http_parser_parse_url(
				value_to_process.data(),
				value_to_process.size(),
				HTTP_CONNECT == m_request_state->m_parser.method,
				&parser_url );
		if( parse_url_result )
			return update_request_target_failure_t{
					fmt::format( "unable to parse request-target, "
							"http_parser_parse_url result: {}",
							parse_url_result )
			};

		const auto is_component_present = [&]( unsigned int component ) -> bool
			{
				return parser_url.field_set & (1u << component);
			};

		const auto try_extract_url_component =
			[&]( unsigned int component ) -> std::string_view
			{
				std::string_view result;
				if( is_component_present(component) )
					result = std::string_view{
							value_to_process.data() +
									parser_url.field_data[component].off,
							parser_url.field_data[component].len
					};
				return result;
			};

		const auto path = try_extract_url_component( UF_PATH );
		const auto query = try_extract_url_component( UF_QUERY );
		const auto fragment = try_extract_url_component( UF_FRAGMENT );

		m_request_info.m_request_target.clear();

		// Если request-target задан в authority-form, то после парсинга
		// path может оказаться пустым.
		if( !path.empty() )
			m_request_info.m_request_target.append( path.data(), path.size() );
		else
			m_request_info.m_request_target += '/';

		if( !query.empty() )
		{
			m_request_info.m_request_target += '?';
			m_request_info.m_request_target.append( query.data(), query.size() );
		}

		if( !fragment.empty() )
		{
			m_request_info.m_request_target += '#';
			m_request_info.m_request_target.append( fragment.data(), fragment.size() );
		}

		return update_request_target_success_t{};
	}

	void
	initiate_authentification(
		can_throw_t /*can_throw*/,
		username_password_extraction_result_t & username_password_info,
		target_host_and_port_extraction_result_t & target_host_and_port_info )
	{
		std::optional< std::string > username;
		std::optional< std::string > password;
		if( auto * upi = std::get_if<username_password_t>(
				&username_password_info ) )
		{
			username = std::move(upi->m_username);
			password = std::move(upi->m_password);
		}

		// Информация о целевом узле и целевом порте должна быть сохранена
		// в request_info, поскольку она потребуется впоследствии.
		{
			auto & host_port =
				std::get< target_host_and_port_t >( target_host_and_port_info );
			m_request_info.m_target_host = std::move(host_port.m_host);
			m_request_info.m_target_port = host_port.m_port;
		}

		context().async_authentificate(
				m_id,
				authentification::request_params_t {
					// Пока работаем только с IPv4 адресами на входе,
					// поэтому не ждем ничего другого.
					m_connection.remote_endpoint().address().to_v4(),
					std::move(username),
					std::move(password),
					m_request_info.m_target_host,
					m_request_info.m_target_port
				},
				with<authentification::result_t>().make_handler(
					[this](
						delete_protector_t delete_protector,
						can_throw_t can_throw,
						authentification::result_t result )
					{
						on_authentification_result(
								delete_protector, can_throw, result );
					} )
			);
	}

	void
	on_authentification_result(
		delete_protector_t delete_protector,
		can_throw_t can_throw,
		authentification::result_t & result )
	{
		std::visit( ::arataga::utils::overloaded{
				[&]( authentification::success_t & info )
				{
					// Передаем управление следующему handler-у.
					replace_handler(
							delete_protector,
							can_throw,
							[this, &info]( can_throw_t )
							{
								return make_dns_lookup_handler(
										std::move(m_ctx),
										m_id,
										std::move(m_connection),
										std::move(m_request_state),
										std::move(m_request_info),
										std::move(info.m_traffic_limiter) );
							} );
				},
				[&]( const authentification::failure_t & info )
				{
					::arataga::logging::wrap_logging(
							proxy_logging_mode,
							spdlog::level::warn,
							[this, can_throw, &info]( auto level )
							{
								log_message_for_connection(
										can_throw,
										level,
										fmt::format(
												"user is not authentificated, reason: {}",
												authentification::to_string_view(
														info.m_reason ) ) );
							} );

					send_negative_response_then_close_connection(
							delete_protector,
							can_throw,
							remove_reason_t::protocol_error,
							response_proxy_auth_required_not_authorized );
				}
			},
			result );
	}
};

//
// make_authentification_handler
//
[[nodiscard]]
connection_handler_shptr_t
make_authentification_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	http_handling_state_unique_ptr_t request_state,
	request_info_t request_info )
{
	return std::make_shared< authentification_handler_t >(
			std::move(ctx),
			id,
			std::move(connection),
			std::move(request_state),
			std::move(request_info) );
}

} /* namespace arataga::acl_handler */

} /* namespace handlers::http */

