/*!
 * @file
 * @brief Реализация initial_http_handler-а.
 */

#include <arataga/acl_handler/handlers/http/basics.hpp>
#include <arataga/acl_handler/handlers/http/factories.hpp>
#include <arataga/acl_handler/handlers/http/helpers.hpp>
#include <arataga/acl_handler/handlers/http/responses.hpp>

#include <arataga/utils/overloaded.hpp>
#include <arataga/utils/subview_of.hpp>

#include <restinio/helpers/http_field_parsers/connection.hpp>

#include <algorithm>
#include <iterator>

namespace arataga::acl_handler
{

namespace handlers::http
{

//
// initial_http_handler_t
//
/*!
 * @brief Первоначальный обработчик HTTP-соединения.
 *
 * Этот обработчик решает что с соединением делать дальше.
 */
class initial_http_handler_t final : public basic_http_handler_t
{
	// Специальный индикатор того, что мы находимся в правильном
	// состоянии перед сменой connection-handler-а.
	struct valid_state_t {};

	// Специальный индикатор того, что состояние initial_http_handler-а
	// перед сменой connection-handler-а некорректно и смену делать
	// нельзя. Вместо этого нужно отослать отрицательный ответ и
	// закрыть соединение.
	struct invalid_state_t
	{
		//! Содержимое отрицательного ответа, который нужно отослать клиенту.
		std::string_view m_response;
	};

	//! Тип результата проверки валидности полученного запроса.
	using validity_check_result_t = std::variant<
			valid_state_t, invalid_state_t >;

	//! Состояние обработки исходного запроса.
	http_handling_state_unique_ptr_t m_request_state;

	//! Дополнительная информация, которая будет накапливаться в
	//! процессе разбора исходного запроса.
	request_info_t m_request_info;

	//! Свойства для HTTP-парсера.
	http_parser_settings m_http_parser_settings;

	//! Признак того, что начался разбор входящего запроса.
	/*!
	 * Если клиент использует keep-alive соединения, то может оказаться
	 * так, что клиент присылает первый запрос, этот запрос обрабатывается,
	 * клиенту отсылают ответ. После чего для этого же соединения создается
	 * новый connection-handler. Но больше в это соединение клиент ничего
	 * не присылает.
	 *
	 * В таком случае соединение с клиентом после истечения тайм-аута
	 * нужно просто закрывать, ничего не отсылая в сторону клиента.
	 * А для этого нужно знать, начался ли разбор сообщения или нет
	 *
	 * Для чего и нужен данный флаг, который будет устанавливаться
	 * в on_message_begin().
	 */
	bool m_incoming_message_started{ false };

	//! Признак того, что нужно переходить к созданию следующего
	//! connection-handler-а.
	bool m_should_next_handler_be_created{ false };

	//! Время, когда соединение было принято.
	std::chrono::steady_clock::time_point m_created_at;

	//! Промежуточный объект для накопления значения имени
	//! текущего HTTP-заголовка.
	std::string m_current_http_field_name;
	//! Промежуточный объект для накопления значения текущего HTTP-заголовка.
	std::string m_current_http_field_value;
	//! Признак того, что значение заголовка было извлечено.
	bool m_on_header_value_called{ false };
	//! Общий объем накопленных заголовков.
	std::size_t m_total_headers_size{ 0u };

	//! Сколько всего байт было разобрано при обработке входящего запроса.
	/*!
	 * Это значение будет использоваться при обработке ошибок чтения
	 * данных из входящего сокета.
	 *
	 * Если сокет закрылся, а ранее из него вообще ничего извлечено
	 * не было, то такую ситуацию нельзя рассматривать как ошибочную
	 * и не нужно ее логировать с уровнями warning или выше.
	 */
	std::size_t m_total_bytes_parsed{ 0u };

public:
	initial_http_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		byte_sequence_t whole_first_pdu,
		std::chrono::steady_clock::time_point created_at )
		:	basic_http_handler_t{ std::move(ctx), id, std::move(connection) }
		,	m_request_state{
				std::make_unique< http_handling_state_t >(
						context().config().io_chunk_size(),
						whole_first_pdu )
			}
		,	m_created_at{ created_at }
	{
		m_request_state->m_parser.data = this;

		// Свойства для HTTP-парсера так же должны быть пронициализированы.
		initialize_http_parser_settings();
	}

protected:
	void
	on_start_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
			delete_protector,
			[this]( delete_protector_t delete_protector, can_throw_t can_throw )
			{
				// Пытаемся разобрать то, что уже есть в буфере.
				try_handle_data_read( delete_protector, can_throw );
			} );
	}

	void
	on_timer_impl( delete_protector_t delete_protector ) override
	{
		if( std::chrono::steady_clock::now() >= m_created_at +
				context().config().http_headers_complete_timeout() )
		{
			wrap_action_and_handle_exceptions(
				delete_protector,
				[this]( delete_protector_t delete_protector, can_throw_t can_throw )
				{
					handle_headers_complete_timeout(
							delete_protector,
							can_throw );
				} );
		}
	}

public:
	std::string_view
	name() const noexcept override
	{
		return "http-initial-handler";
	}

private:
	// Либо просто удаляет connection-handler, если клиент вообще
	// не прислал запроса. Либо же отсылает отрицательный ответ из-за
	// того, что запрос от клиента идет слишком долго.
	void
	handle_headers_complete_timeout(
		delete_protector_t delete_protector,
		can_throw_t can_throw )
	{
		if( m_incoming_message_started )
		{
			// Поскольку клиент начал отсылку запроса, то он должен
			// получить отрицательный ответ с нашей стороны.
			::arataga::logging::wrap_logging(
					proxy_logging_mode,
					spdlog::level::warn,
					[this, can_throw]( auto level )
					{
						log_message_for_connection(
								can_throw,
								level,
								"http_headers_complete timed out" );
					} );

			// Осталось только отослать ответ и закрыть соединение.
			send_negative_response_then_close_connection(
					delete_protector,
					can_throw,
					remove_reason_t::current_operation_timed_out,
					response_request_timeout_headers_complete_timeout );
		}
		else
		{
			// Т.к. запроса не было, то и отсылать ничего не нужно.
			// Достаточно просто закрыть соединение.
			log_and_remove_connection(
					delete_protector,
					can_throw,
					remove_reason_t::http_no_incoming_request,
					spdlog::level::info,
					"no incoming HTTP request for a long time" );
		}
	}

	// Смысл возвращаемого значения такой же, как и в callback-ах
	// для http_parser.
	[[nodiscard]]
	int
	complete_current_field_if_necessary( can_throw_t can_throw )
	{
		if( m_on_header_value_called )
		{
			// Это начало нового заголовка.
			m_total_headers_size +=
					m_current_http_field_name.size() +
					m_current_http_field_value.size();

			if( const auto lim =
					context().config().http_message_limits().m_max_total_headers_size;
					lim < m_total_headers_size )
			{
				::arataga::logging::wrap_logging(
						proxy_logging_mode,
						spdlog::level::err,
						[this, can_throw, &lim]( auto level )
						{
							log_message_for_connection(
									can_throw,
									level,
									fmt::format(
											"total http-fields size exceeds limit: "
											"size={}, limit={}",
											m_total_headers_size,
											lim )
								);
						} );

				return -1;
			}

			m_request_info.m_headers.add_field(
					std::move(m_current_http_field_name),
					std::move(m_current_http_field_value) );

			m_on_header_value_called = false;
		}

		return 0;
	}

	/*!
	 * @name Callback-и для HTTP-парсера.
	 * @{
	 */
	int
	on_message_begin( can_throw_t /*can_throw*/ )
	{
		// Нужно зафиксировать, что новый HTTP-запрос к нам начал доходить.
		// Без этого мы не сможем правильно обрабатывать тайм-ауты.
		m_incoming_message_started = true;

		m_request_info.m_method = static_cast<http_method>(
				m_request_state->m_parser.method);

		// Если у нас HTTP-метод без body, то часть callback-ов должна
		// быть заменена.
		if( helpers::is_bodyless_method( m_request_info.m_method ) )
		{
			m_http_parser_settings.on_headers_complete =
				helpers::make_http_parser_callback<
					&initial_http_handler_t::on_headers_complete_for_bodyless_method >();
			m_http_parser_settings.on_body =
				helpers::make_http_parser_callback<
					&initial_http_handler_t::on_body_for_bodyless_method >();

			m_http_parser_settings.on_chunk_header =
				helpers::make_http_parser_callback<
					&initial_http_handler_t::on_chunk_header_for_bodyless_method >();

			m_http_parser_settings.on_chunk_complete =
				helpers::make_http_parser_callback<
					&initial_http_handler_t::on_chunk_complete_for_bodyless_method >();
			m_http_parser_settings.on_message_complete =
				helpers::make_http_parser_callback<
					&initial_http_handler_t::on_message_complete_for_bodyless_method >();
		}

		return 0;
	}

	int
	on_url( can_throw_t can_throw, const char * data, std::size_t length )
	{
		m_request_info.m_request_target.append( data, length );
		if( const auto lim =
				context().config().http_message_limits().m_max_request_target_length;
				lim < m_request_info.m_request_target.size() )
		{
			::arataga::logging::wrap_logging(
					proxy_logging_mode,
					spdlog::level::err,
					[this, can_throw, &lim]( auto level )
					{
						log_message_for_connection(
								can_throw,
								level,
								fmt::format(
										"request-target exceeds limit: size={}, limit={}",
										m_request_info.m_request_target.size(),
										lim )
							);
					} );

			return -1;
		}

		return 0;
	}

	int
	on_status( can_throw_t can_throw, const char *, std::size_t )
	{
		// Мы не ждем status-а на входящем запросе.
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							"HTTP status found in an incoming HTTP request" );
				} );

		return -1;
	}

	int
	on_header_field(
		can_throw_t can_throw, const char * data, std::size_t length )
	{
		if( const auto rc = complete_current_field_if_necessary( can_throw );
				0 != rc )
		{
			return rc;
		}

		m_current_http_field_name.append( data, length );
		if( const auto lim =
				context().config().http_message_limits().m_max_field_name_length;
				lim < m_current_http_field_name.size() )
		{
			::arataga::logging::wrap_logging(
					proxy_logging_mode,
					spdlog::level::err,
					[this, can_throw, &lim]( auto level )
					{
						log_message_for_connection(
								can_throw,
								level,
								fmt::format(
										"http-field name exceeds limit: "
										"size={}, limit={}",
										m_current_http_field_name.size(),
										lim )
							);
					} );

			return -1;
		}

		return 0;
	}

	int
	on_header_value(
		can_throw_t can_throw, const char * data, std::size_t length )
	{
		m_current_http_field_value.append( data, length );
		m_on_header_value_called = true;
		if( const auto lim =
				context().config().http_message_limits().m_max_field_value_length;
				lim < m_current_http_field_value.size() )
		{
			::arataga::logging::wrap_logging(
					proxy_logging_mode,
					spdlog::level::err,
					[this, can_throw, &lim]( auto level )
					{
						log_message_for_connection(
								can_throw,
								level,
								fmt::format(
										"http-field value exceeds limit: "
										"size={}, limit={}",
										m_current_http_field_value.size(),
										lim )
							);
					} );

			return -1;
		}

		return 0;
	}

	int
	on_headers_complete_for_bodyful_method(
		can_throw_t can_throw )
	{
		if( const auto rc = complete_current_field_if_necessary( can_throw );
				0 != rc )
		{
			return rc;
		}

		// Нужно ставить разбор HTTP-пакета на паузу и переходить
		// к анализу того, что мы уже получили.
		http_parser_pause( &(m_request_state->m_parser), 1 );

		// Для методов, у которых есть BODY, уже можно переходить
		// к созданию следующего обработчика.
		m_should_next_handler_be_created = true;

		return 0;
	}

	int
	on_headers_complete_for_bodyless_method(
		can_throw_t can_throw )
	{
		if( const auto rc = complete_current_field_if_necessary( can_throw );
				0 != rc )
		{
			return rc;
		}

		return 0;
	}

	int
	on_body_for_bodyful_method(
		can_throw_t can_throw, const char *, std::size_t )
	{
		// На этой стадии мы не должны извлекать тело запроса.
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							"unexpected failre: HTTP body extracted by "
							"initial_http_handler" );
				} );

		return -1;
	}

	int
	on_body_for_bodyless_method(
		can_throw_t can_throw, const char *, std::size_t )
	{
		// У метода, который не предполагает наличия тела запроса, это
		// самое тело запроса нашлось.
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							fmt::format( "unexpected failre: HTTP body for "
									"bodyless method {}",
									http_method_str( m_request_info.m_method ) )
						);
				} );

		return -1;
	}

	int
	on_message_complete_for_bodyful_method(
		can_throw_t can_throw )
	{
		// На этой стадии мы не должны достичь конца тела HTTP-сообщения.
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							"unexpected failre: HTTP message completed "
							"by initial_http_handler" );
				} );

		return -1;
	}

	int
	on_message_complete_for_bodyless_method( can_throw_t /*can_throw*/ )
	{
		// Для HTTP-методов, у которых нет BODY, уже можно переходить
		// к созданию следующего handler-а.
		m_should_next_handler_be_created = true;

		return 0;
	}

	int
	on_chunk_header_for_bodyful_method(
		can_throw_t can_throw )
	{
		// На этой стадии мы не должны иметь дел с chunk-ами.
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							"unexpected failre: HTTP body chunk extracted "
							"by initial_http_handler" );
				} );

		return -1;
	}

	int
	on_chunk_header_for_bodyless_method(
		can_throw_t can_throw )
	{
		// У метода, который не предполагает наличия тела запроса, это
		// самое тело запроса нашлось.
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							fmt::format( "unexpected failre: HTTP body chunk for "
									"bodyless method {}",
									http_method_str( m_request_info.m_method ) )
						);
				} );

		return -1;
	}

	int
	on_chunk_complete_for_bodyful_method(
		can_throw_t can_throw )
	{
		// На этой стадии мы не должны иметь дел с chunk-ами.
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							"unexpected failre: HTTP body chunk completed "
							"by initial_http_handler" );
				} );

		return -1;
	}

	int
	on_chunk_complete_for_bodyless_method(
		can_throw_t can_throw )
	{
		// У метода, который не предполагает наличия тела запроса, это
		// самое тело запроса нашлось.
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							fmt::format( "unexpected failre: HTTP body chunk for "
									"bodyless method {}",
									http_method_str( m_request_info.m_method ) )
						);
				} );

		return -1;
	}

	/*!
	 * @}
	 */

	void
	initialize_http_parser_settings()
	{
		http_parser_settings_init( &m_http_parser_settings );
		m_http_parser_settings.on_message_begin =
			helpers::make_http_parser_callback<
					&initial_http_handler_t::on_message_begin >();

		m_http_parser_settings.on_url =
			helpers::make_http_parser_callback<
					&initial_http_handler_t::on_url >();

		m_http_parser_settings.on_status =
			helpers::make_http_parser_callback<
					&initial_http_handler_t::on_status >();

		m_http_parser_settings.on_header_field =
			helpers::make_http_parser_callback<
					&initial_http_handler_t::on_header_field >();

		m_http_parser_settings.on_header_value =
			helpers::make_http_parser_callback<
					&initial_http_handler_t::on_header_value >();

		m_http_parser_settings.on_headers_complete =
			helpers::make_http_parser_callback<
					&initial_http_handler_t::on_headers_complete_for_bodyful_method >();

		m_http_parser_settings.on_body =
			helpers::make_http_parser_callback<
					&initial_http_handler_t::on_body_for_bodyful_method >();

		m_http_parser_settings.on_message_complete =
			helpers::make_http_parser_callback<
					&initial_http_handler_t::on_message_complete_for_bodyful_method >();

		m_http_parser_settings.on_chunk_header =
			helpers::make_http_parser_callback<
					&initial_http_handler_t::on_chunk_header_for_bodyful_method >();

		m_http_parser_settings.on_chunk_complete =
			helpers::make_http_parser_callback<
					&initial_http_handler_t::on_chunk_complete_for_bodyful_method >();
	}

	void
	try_handle_data_read(
		delete_protector_t delete_protector,
		can_throw_t can_throw )
	{
		const auto bytes_to_parse = m_request_state->m_incoming_data_size
				- m_request_state->m_next_execute_position;

		const auto bytes_parsed = http_parser_execute(
				&(m_request_state->m_parser),
				&m_http_parser_settings,
				&(m_request_state->m_incoming_data.at(
					m_request_state->m_next_execute_position)),
				bytes_to_parse );
		m_request_state->m_next_execute_position += bytes_parsed;

		if( HPE_OK != m_request_state->m_parser.http_errno &&
				HPE_PAUSED != m_request_state->m_parser.http_errno )
		{
			::arataga::logging::wrap_logging(
					proxy_logging_mode,
					spdlog::level::err,
					[this, can_throw]( auto level )
					{
						log_message_for_connection(
								can_throw,
								level,
								fmt::format( "http_parser returned an error: {}",
										http_errno_name( static_cast<http_errno>(
													m_request_state->m_parser.http_errno) ) )
							);
					} );

			// Возникла ошибка, которая не позволяет нам продолжать
			// обработку этого соединения.
			return send_negative_response_then_close_connection(
					delete_protector,
					can_throw,
					remove_reason_t::protocol_error,
					response_bad_request_parse_error_detected );
		}

		m_total_bytes_parsed += bytes_parsed;

		// Возможно, уже пришло время переходить к следующей стадии.
		if( m_should_next_handler_be_created )
		{
			return initiate_switch_to_next_handler(
					delete_protector,
					can_throw );
		}

		// Если мы все еще здесь, значит данных во входящем буфере
		// недостаточно и нужно читать следующую порцию.
		// Но на всякий случай проверим, так ли это.

		// Все данные должны быть разобраны. Если нет, то это проблема.
		if( bytes_to_parse != bytes_parsed )
		{
			throw acl_handler_ex_t{
					fmt::format( "unexpected case: bytes_to_parse ({}) != "
							"bytes_parsed ({}), handling can't be continued",
							bytes_to_parse, bytes_parsed )
			};
		}

		// Все, что нам остается -- это инициировать чтение следующей порции
		// данных.
		m_request_state->m_incoming_data_size = 0u;
		// Используем async_read_some для того, чтобы самостоятельно
		// обрабатывать ситуацию с EOF.
		auto buffer = asio::buffer(
				&(m_request_state->m_incoming_data[0]),
				m_request_state->m_incoming_data.size() );
		m_connection.async_read_some(
				buffer,
				with<const asio::error_code &, std::size_t>().make_handler(
					[this](
						delete_protector_t delete_protector,
						can_throw_t can_throw,
						const asio::error_code & ec, std::size_t bytes )
					{
						on_read_result( delete_protector, can_throw, ec, bytes );
					} )
			);
	}

	// Обработка заголовков типа Connection и Proxy-Connection.
	std::optional< invalid_state_t >
	handle_connection_header(
		can_throw_t can_throw,
		std::string_view field_name )
	{
		std::optional< invalid_state_t > opt_error;

		using namespace restinio::http_field_parsers;

		// Сперва соберем значения из всех заголовков Connection
		// в одно место.
		connection_value_t aggregated;
		m_request_info.m_headers.for_each_value_of(
				field_name,
				[&]( const auto field_value ) {
					const auto r = connection_value_t::try_parse( field_value );
					if( r )
					{
						std::move( r->values.begin(), r->values.end(),
								std::back_inserter( aggregated.values ) );

						return restinio::http_header_fields_t::continue_enumeration();
					}
					else
					{
						// Возникла ошибка разбора очередного заголовка.
						::arataga::logging::wrap_logging(
								proxy_logging_mode,
								spdlog::level::err,
								[this, can_throw, &field_name, &field_value, &r](
									auto level )
								{
									log_message_for_connection(
											can_throw,
											level,
											fmt::format(
													"unexpected case: unable to parse "
													"value of {} header: {}",
													field_name,
													make_error_description(
															r.error(), field_value )
											) );
								} );

						opt_error = invalid_state_t{
								response_bad_request_parse_error_detected
							};

						// Идти дальше нет смысла.
						return restinio::http_header_fields_t::stop_enumeration();
					}
				} );

		// Теперь осталось пройтись по полученным значениям и обработать
		// их должным образом.
		for( const auto & v : aggregated.values )
		{
			if( "close" == v )
				// Соединение с клиентом должно быть закрыто после обработки
				// запроса.
				m_request_info.m_keep_user_end_alive = false;
			else
			{
				// Все остальные значения воспринимаем как имена заголовков,
				// которые нужно удалить.
				// Однако, заголовок Transfer-Encoding нужно оставить, т.к.
				// мы не производим трансформацию содержимого тела запроса,
				// а отдаем на целевой узел все именно так, как оно пришло
				// от клиента.
				if( "transfer-encoding" != v )
					m_request_info.m_headers.remove_all_of( v );
			}
		}

		// Заголовок Connection так же нужно удалить.
		m_request_info.m_headers.remove_all_of( field_name );

		return opt_error;
	}

	void
	remove_hop_by_hop_headers()
	{
		using namespace std::string_view_literals;
		// Выбрасываем заголовки, которые являются hop-to-hop
		// заголовками и не должны уходить из прокси на целевой узел.
		//
		// ПРИМЕЧАНИЕ: выбрасываем не все заголовки. Так, оставляем
		// следующие заголовки:
		// - Proxy-Authorization, т.к. он потребуется на следующем шаге
		// и будет удален впоследствии;
		// - Transfer-Encoding, т.к. мы отдаем содержимое именно в том
		// виде, в котором получаем от клиента.
		//
		// Перечень hop-to-hop заголовков найден здесь:
		// https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection
		static constexpr std::initializer_list< std::string_view >
			hop_by_hop_headers{
					"Keep-Alive"sv, "TE"sv, "Trailer"sv, "Proxy-Authentificate"sv
			};

		for( const auto & h : hop_by_hop_headers )
			m_request_info.m_headers.remove_all_of( h );
	}

	// Выполнение необходимых модификаций в заголовках полученного
	// запроса.
	// Может возвращаться invalid_state_t если в процессе обработки
	// заголовков обнаружится какая-то ошибка в значении заголовка или
	// возникнет ошибка разбора содержимого заголовка.
	std::optional< invalid_state_t >
	try_modify_request_headers( can_throw_t can_throw )
	{
		std::optional< invalid_state_t > opt_error;

		opt_error = handle_connection_header( can_throw, "Connection" );
		if( opt_error )
			return *opt_error;

		opt_error = handle_connection_header( can_throw, "Proxy-Connection" );
		if( opt_error )
			return *opt_error;

		remove_hop_by_hop_headers();

		return opt_error;
	}

	validity_check_result_t
	ensure_valid_state_before_switching_handler( can_throw_t can_throw )
	{
		// Если мы сейчас обрабатываем HTTP CONNECT, то нужно убедиться
		// в том, что входной буфер пуст и после самого запроса там
		// ничего не осталось.
		if( HTTP_CONNECT == m_request_info.m_method )
		{
			if( m_request_state->m_incoming_data_size
				!= m_request_state->m_next_execute_position )
			{
				::arataga::logging::wrap_logging(
						proxy_logging_mode,
						spdlog::level::err,
						[this, can_throw]( auto level )
						{
							log_message_for_connection(
									can_throw,
									level,
									fmt::format(
											"unexpected case: incoming buffer is not "
											"empty after parsing HTTP message with "
											"CONNECT request; buffer_size: {}, "
											"parsed_data_size: {}",
											m_request_state->m_incoming_data_size,
											m_request_state->m_next_execute_position )
								);
						} );

				return invalid_state_t{
						response_bad_request_unexpected_parsing_error
					};
			}
		}

		auto opt_error = try_modify_request_headers( can_throw );
		if( opt_error )
			return *opt_error;

		return valid_state_t{};
	}

	void
	initiate_switch_to_next_handler(
		delete_protector_t delete_protector,
		can_throw_t can_throw )
	{
		// Логирование для облегчения последующих разбирательств по логам.
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::info,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							fmt::format( "incoming-request={}, request-target={}",
									http_method_str( m_request_info.m_method ),
									::arataga::utils::subview_of<100>(
											m_request_info.m_request_target )
							)
						);
				} );

		// Перед переходом к другому обработчику нужно убедится,
		// что нигде не осталось никакого мусора.
		std::visit(
			::arataga::utils::overloaded{
				[&]( const valid_state_t & ) {
					// Далее работу будет выполнять другой обработчик.
					replace_handler(
							delete_protector,
							can_throw,
							[this]( can_throw_t )
							{
								return make_authentification_handler(
									std::move(m_ctx),
									m_id,
									std::move(m_connection),
									std::move(m_request_state),
									std::move(m_request_info) );
							} );
				},
				[&]( const invalid_state_t & err ) {
					send_negative_response_then_close_connection(
							delete_protector,
							can_throw,
							remove_reason_t::protocol_error,
							err.m_response );
				}
			},
			ensure_valid_state_before_switching_handler( can_throw ) );
	}

	void
	on_read_result(
		delete_protector_t delete_protector,
		can_throw_t can_throw,
		const asio::error_code & ec,
		std::size_t bytes_transferred )
	{
		if( ec )
		{
			remove_reason_t reason = remove_reason_t::io_error;

			// Нам в любом случае нужно удалять самих себя, но нужно
			// выяснить, с какой именно диагностикой это следует делать.
			if( asio::error::operation_aborted == ec )
				reason = remove_reason_t::current_operation_canceled;
			else if( asio::error::eof == ec )
			{
				reason = remove_reason_t::user_end_closed_by_client;

				// Если мы вообще еще ничего не начали разбирать, то закрытие
				// соединения на стороне пользователя -- это не проблема.
				// Такое может происходить при keep-alive соединениях,
				// когда пользователь выполняет всего один запрос, затем
				// закрывает соединение после получения ответа.
				if( m_total_bytes_parsed )
				{
					::arataga::logging::wrap_logging(
							proxy_logging_mode,
							spdlog::level::warn,
							[this, can_throw]( auto level )
							{
								log_message_for_connection(
										can_throw,
										level,
										fmt::format(
												"user_end closed by client after "
												"parsing {} byte(s) of incoming request",
												m_total_bytes_parsed ) );
							} );
				}
			}

			// Если это все-таки ошибка ввода-вывода, то сей факт
			// должен быть залогирован перед закрытием соединения.
			if( remove_reason_t::io_error == reason )
				log_and_remove_connection_on_io_error(
						delete_protector,
						can_throw,
						ec,
						"reading incoming HTTP-request" );
			else
				// Просто удаляем самих себя.
				remove_handler( delete_protector, reason );
		}
		else
		{
			// Ошибок нет, обрабатываем прочитанные данные.
			on_data_read( delete_protector, can_throw, bytes_transferred );
		}
	}

	void
	on_data_read(
		delete_protector_t delete_protector,
		can_throw_t can_throw,
		std::size_t bytes_transferred )
	{
		m_request_state->m_incoming_data_size = bytes_transferred;

		// Разбор нужно вести с самого начала буфера, поскольку все
		// содержимое буфера было полностью заменено.
		m_request_state->m_next_execute_position = 0u;

		try_handle_data_read( delete_protector, can_throw );
	}
};

} /* namespace arataga::acl_handler */

[[nodiscard]]
connection_handler_shptr_t
make_http_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	byte_sequence_t whole_first_pdu,
	std::chrono::steady_clock::time_point created_at )
{
	return std::make_shared< handlers::http::initial_http_handler_t >(
			std::move(ctx),
			id,
			std::move(connection),
			whole_first_pdu,
			created_at );
}

} /* namespace handlers::http */

