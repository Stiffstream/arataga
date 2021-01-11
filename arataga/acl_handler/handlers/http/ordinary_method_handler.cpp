/*!
 * @file
 * @brief Реализация connection_handler-а для обработки обычных HTTP методов.
 */

#include <arataga/acl_handler/handlers/http/basics.hpp>
#include <arataga/acl_handler/handlers/http/factories.hpp>
#include <arataga/acl_handler/handlers/http/helpers.hpp>
#include <arataga/acl_handler/handlers/http/responses.hpp>

#include <arataga/acl_handler/handler_factories.hpp>
#include <arataga/acl_handler/out_data_piece.hpp>

#include <arataga/utils/subview_of.hpp>

#include <restinio/helpers/http_field_parsers/connection.hpp>

#include <noexcept_ctcheck/pub.hpp>

#include <list>
#include <iterator>

namespace arataga::acl_handler
{

namespace handlers::http
{

//
// ordinary_method_handler_t
//
/*!
 * @brief Обработчик соединения, который обрабатывает HTTP-методы,
 * отличные от CONNECT (вроде GET, POST, DELETE и т.д.).
 */
class ordinary_method_handler_t final : public handler_with_out_connection_t
{
	//! Перечень состояний обработки status-line в ответе от целевого узла.
	enum class status_line_processing_stage_t
	{
		not_started,
		status_code_written,
		completed
	};

	//! Состояние обработки ответа.
	struct response_processing_state_t
	{
		//! Содержимое status-line.
		/*!
		 * Опустошается после записи в ответ клиенту.
		 */
		std::string m_status_line;

		//! Была ли полностью завершена status-line?
		status_line_processing_stage_t m_status_line_stage{
				status_line_processing_stage_t::not_started
			};

		//! Имя очередного заголовка.
		std::string m_last_header_name;
		//! Значение очередного заголовка.
		std::string m_last_header_value;
		//! Признак того, что значение заголовка было извлечено.
		bool m_on_header_value_called{ false };
		//! Общая длина разобранных заголовков.
		std::size_t m_total_headers_size{ 0u };

		//! Заголовки из ответа, которые уже были получены.
		restinio::http_header_fields_t m_headers;

		//! Признак того, что разбор обычных заголовков завершился.
		bool m_leading_headers_completed{ false };
	};

	//! Возможные варианты состояния обработки HTTP-сообщения в этом
	//! направлении.
	enum incoming_http_message_stage_t
	{
		//! Входящее сообщение еще полностью не вычитано.
		in_progress,
		//! HTTP-сообщение полностью вычитано. Больше не нужно ничего
		//! читать из этого направления.
		message_completed
	};

	//! Тип указателя на метод, который должен быть вызван после
	//! успешного завершения записи исходящих данных в то или иное
	//! соединение.
	using write_completed_handler_t =
		void (ordinary_method_handler_t::*)(
				delete_protector_t, can_throw_t);

	/*!
	 * @brief Состояние одного направления передачи данных.
	 *
	 * Этот объект формируется уже после того, как подключение от клиента
	 * было первично обработано и клиент был аутентифицирован.
	 */
	struct direction_state_t
	{
		using out_piece_container_t = std::list< out_data_piece_t >;

		//! Состояние разбора http-сообщений в этом направлении.
		http_handling_state_unique_ptr_t m_http_state;

		//! Параметры парсинга http-сообщений в этом направлении.
		http_parser_settings m_http_parser_settings;

		//! Сокет, который отвечает за это направление.
		asio::ip::tcp::socket & m_channel;

		//! Название этого направления.
		/*!
		 * @attention
		 * Исходим из того, что это string_view для строкового литерала.
		 */
		const std::string_view m_name;

		//! Список ожидающих отправки блоков данных.
		out_piece_container_t m_pieces_read;

		//! Тип этого направления для учета в traffic_limiter.
		traffic_limiter_t::direction_t m_traffic_direction;

		//! Живо ли еще данное направление?
		/*!
		 * Направление живо пока не было диагностировано его закрытие.
		 */
		bool m_is_alive{ true };

		//! Превышен ли лимит трафика по этому направлению?
		bool m_is_traffic_limit_exceeded{ false };

		//! Статус обработки входящего HTTP-сообщения по этому направлению.
		incoming_http_message_stage_t m_incoming_message_stage{
				incoming_http_message_stage_t::in_progress
			};

		//! Обработчик, который должен быть вызван после записи
		//! данных, прочитанных из этого направления.
		write_completed_handler_t m_on_write_completed;

		//! Сколько байт было отослано в это направление из противоположного
		//! направления.
		/*!
		 * Если это user_end, то данное значение указывает, сколько байт,
		 * прочитанных из target_end, было записано в user_end.
		 *
		 * Это счетчик байт, которые были отосланы в канал. Возможно,
		 * что реально записано в канал меньше, т.к. очередная операция
		 * записи еще может быть незавершена.
		 */
		std::uint_least64_t m_bytes_from_opposite_dir{ 0u };

		direction_state_t(
			http_handling_state_unique_ptr_t http_state,
			asio::ip::tcp::socket & channel,
			std::string_view name,
			traffic_limiter_t::direction_t traffic_direction,
			write_completed_handler_t on_write_completed )
			:	m_http_state{ std::move(http_state) }
			,	m_channel{ channel }
			,	m_name{ name }
			,	m_traffic_direction{ traffic_direction }
			,	m_on_write_completed{ on_write_completed }
		{}

		[[nodiscard]]
		bool
		is_dead() const noexcept
		{
			return !m_is_alive;
		}
	};

	//! Краткое описание обрабатываемого запроса.
	/*!
	 * Это описание нам нужно хранить для организации нормального
	 * логирования.
	 */
	struct brief_request_info_t
	{
		//! HTTP-метод для запроса.
		http_method m_method;

		//! Значение request-target, которое будет использовано в запросе.
		std::string m_request_target;

		//! Значение заголовка Host, который будет передан в запросе.
		std::string m_host_field_value;

		//! Нужно ли сохранять соединение с клиентом после обработки
		//! его запроса.
		bool m_keep_user_end_alive;
	};

	//! Ограничитель трафика для этого клиента.
	traffic_limiter_unique_ptr_t m_traffic_limiter;

	//! Состояние направления от клиента к целевому узлу.
	direction_state_t m_user_end;
	//! Состояние направления от целевого узла к клиенту.
	direction_state_t m_target_end;

	//! Время последнего успешного чтения данных (из любого соединения).
	std::chrono::steady_clock::time_point m_last_read_at{
			std::chrono::steady_clock::now()
		};

	//! Состояние обработки ответа от целевого узла.
	response_processing_state_t m_response_processing_state;

	//! Краткое описание обрабатываемого запроса.
	const brief_request_info_t m_brief_request_info;

public:
	ordinary_method_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket in_connection,
		http_handling_state_unique_ptr_t request_state,
		request_info_t request_info,
		traffic_limiter_unique_ptr_t traffic_limiter,
		asio::ip::tcp::socket out_connection )
		:	handler_with_out_connection_t{
				std::move(ctx),
				id,
				std::move(in_connection),
				std::move(out_connection)
			}
		,	m_traffic_limiter{ std::move(traffic_limiter) }
		,	m_user_end{
				std::move(request_state),
				m_connection,
				"user_end",
				traffic_limiter_t::direction_t::from_user,
				&ordinary_method_handler_t::
						user_end_default_write_completed_handler
			}
		,	m_target_end{
				std::make_unique< http_handling_state_t >(
						context().config().io_chunk_size(),
						byte_sequence_t{} ),
				m_out_connection,
				"target_end",
				traffic_limiter_t::direction_t::from_target,
				&ordinary_method_handler_t::
						target_end_default_write_completed_handler
			}
		,	m_brief_request_info{ make_brief_request_info( request_info ) }
	{
		// В конструкторе можно бросать исключения.
		::arataga::utils::exception_handling_context_t exception_ctx;

		tune_http_settings( exception_ctx.make_can_throw_marker() );

		// У вызова этого метода в конструкторе есть отрицательная сторона:
		// если в процессе обработки остатка входящих данных возникнет
		// исключение, то оно вылетит наружу и приведет к тому, что
		// соединение от клиента будет закрыто без отсылки какого-либо
		// HTTP-ответа в соединение. Т.е. клиент вместо "400 Bad Request"
		// получит просто разрыв.
		//
		// Чтобы это исправить нужно переносить данный вызов в on_start.
		// Но это приведет к необходимости сохранять в handler-е значение
		// request_info.
		//
		// Но даже перенос в on_start не гарантирует отсылки отрицательного
		// ответа во всех случаях. Так, основных причин для выброса исключений
		// две:
		// 
		// 1. Неправильные данные во входном потоке. Но эти неправильные
		// данные могут быть обнаружены во входном потоке в любой момент,
		// не обязательно в начале HTTP-сообщения. Так, при chunked encoding
		// можно успешно выкачать несколько chunk-ов и передать их на сторону
		// целевого узла и только потом получить ошибку. При этом уже может
		// начаться передача ответа от целевого узла клиенту.
		//
		// 2. Невозможность выделить память или какая-то другая ситуация,
		// из-за которой нет возможности разобрать входящий поток. Такая
		// ситуация может возникнуть уже после того, как ответ от целевого
		// узла может начать транслироваться в строну клиента. Кроме того,
		// если будет выброшен bad_alloc, то не факт, то получится
		// отослать ответное сообщение.
		//
		// Поэтому пока вызов make_user_end_outgoing_data оставлен здесь.
		make_user_end_outgoing_data(
				exception_ctx.make_can_throw_marker(),
				request_info );
	}

protected:
	void
	on_start_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
			delete_protector,
			[this]( delete_protector_t, can_throw_t can_throw )
			{
				// Это логирование упрощает разбирательство с проблемами
				// по логам.
				::arataga::logging::wrap_logging(
						proxy_logging_mode,
						spdlog::level::info,
						[this, can_throw]( auto level )
						{
							log_message_for_connection(
									can_throw,
									level,
									fmt::format( "outgoing-request={}, host={}, "
											"request-target={}",
											http_method_str( m_brief_request_info.m_method ),
											::arataga::utils::subview_of<100>(
													m_brief_request_info.m_host_field_value ),
											::arataga::utils::subview_of<100>(
													m_brief_request_info.m_request_target )
									)
								);
						} );

				// В user_end 100% есть данные, которые должны быть
				// отосланы в target_end.
				write_data_read_from( can_throw, m_user_end, m_target_end );

				// Сразу же запускаем чтение данных от целевого узла.
				initiate_async_read_for_direction( can_throw, m_target_end );
			} );
	}

	void
	on_timer_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
			delete_protector,
			[this]( delete_protector_t delete_protector, can_throw_t can_throw ) {
			{
				// Так быть не должно, но на всякий случай сделаем проверку...
				if( m_user_end.is_dead() && m_target_end.is_dead() )
				{
					return log_and_remove_connection(
							delete_protector,
							can_throw,
							remove_reason_t::unexpected_and_unsupported_case,
							spdlog::level::warn,
							"both connections are closed" );
				}
			}

			{
				// Какое-то из соединений еще живо. Поэтому можно
				// проверять время отсутствия активности.
				const auto now = std::chrono::steady_clock::now();

				if( m_last_read_at +
						context().config().idle_connection_timeout() < now )
				{
					return log_and_remove_connection(
							delete_protector,
							can_throw,
							remove_reason_t::no_activity_for_too_long,
							spdlog::level::warn,
							"no data read for long time" );
				}
			}

			// Если по каким-то направлениям был превышен лимит,
			// то нужно проверить лимит еще раз, и если можно, то
			// инициировать новые операции ввода-вывода.
			// Особенность обработки этой ситуации конкретно для HTTP в том,
			// что здесь лимит проверяется при выполнении записи, а не чтения.
			if( m_user_end.m_is_traffic_limit_exceeded )
			{
				initiate_write_outgoing_data_or_read_next_incoming_portion(
						can_throw, m_user_end, m_target_end );
			}
			if( m_target_end.m_is_traffic_limit_exceeded )
			{
				initiate_write_outgoing_data_or_read_next_incoming_portion(
						can_throw, m_target_end, m_user_end );
			}
		} );
	}

public:
	std::string_view
	name() const noexcept override
	{
		return "http-ordinary-method-handler";
	}

private:
	[[nodiscard]]
	brief_request_info_t
	make_brief_request_info( const request_info_t & info )
	{
		brief_request_info_t result;

		result.m_method = info.m_method;
		result.m_request_target = info.m_request_target;

		// Как оказалось, не все HTTP-сервера любят, когда в Host порт 80
		// задается явно. Поэтому, если target_port==80, то в Host указываем
		// только имя хоста. А target_port добаляем только если это не 80.
		if( 80u == info.m_target_port )
			result.m_host_field_value = info.m_target_host;
		else
			result.m_host_field_value = fmt::format( "{}:{}",
							info.m_target_host,
							info.m_target_port );

		result.m_keep_user_end_alive = info.m_keep_user_end_alive;

		return result;
	}

	void
	tune_http_settings( can_throw_t /*can_throw*/ )
	{
		// http_parser для направления user_end уже был проинициализирован,
		// но он стоит на паузе и у него осталось старое значение data.
		m_user_end.m_http_state->m_parser.data = this;
		http_parser_pause( &(m_user_end.m_http_state->m_parser), 0 );

		// А вот http_parser для направления target_end должен быть
		// инициализирован.
		http_parser_init( &(m_target_end.m_http_state->m_parser), HTTP_RESPONSE );
		m_target_end.m_http_state->m_parser.data = this;

		// Обработчики того, что идет от клиента.
		http_parser_settings_init( &m_user_end.m_http_parser_settings );

		m_user_end.m_http_parser_settings.on_message_begin =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::user_end__on_message_begin >();

		m_user_end.m_http_parser_settings.on_url =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::user_end__on_url >();

		m_user_end.m_http_parser_settings.on_status =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::user_end__on_status >();

		m_user_end.m_http_parser_settings.on_header_field =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::user_end__on_header_field >();

		m_user_end.m_http_parser_settings.on_header_value =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::user_end__on_header_value >();

		m_user_end.m_http_parser_settings.on_headers_complete =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::user_end__on_headers_complete >();

		m_user_end.m_http_parser_settings.on_body =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::user_end__on_body >();

		m_user_end.m_http_parser_settings.on_message_complete =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::user_end__on_message_complete >();

		m_user_end.m_http_parser_settings.on_chunk_header =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::user_end__on_chunk_header >();

		m_user_end.m_http_parser_settings.on_chunk_complete =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::user_end__on_chunk_complete >();

		// Обработчики того, что идет от целевого узла.
		http_parser_settings_init( &m_target_end.m_http_parser_settings );

		m_target_end.m_http_parser_settings.on_message_begin =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::target_end__on_message_begin >();

		m_target_end.m_http_parser_settings.on_url =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::target_end__on_url >();

		m_target_end.m_http_parser_settings.on_status =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::target_end__on_status >();

		m_target_end.m_http_parser_settings.on_header_field =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::target_end__on_header_field >();

		m_target_end.m_http_parser_settings.on_header_value =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::target_end__on_header_value >();

		m_target_end.m_http_parser_settings.on_headers_complete =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::target_end__on_headers_complete >();

		m_target_end.m_http_parser_settings.on_body =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::target_end__on_body >();

		m_target_end.m_http_parser_settings.on_message_complete =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::target_end__on_message_complete >();

		m_target_end.m_http_parser_settings.on_chunk_header =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::target_end__on_chunk_header >();

		m_target_end.m_http_parser_settings.on_chunk_complete =
			helpers::make_http_parser_callback<
					&ordinary_method_handler_t::target_end__on_chunk_complete >();
	}

	void
	make_user_end_outgoing_data(
		can_throw_t can_throw,
		const request_info_t & request_info )
	{
		// Вместо того, чтобы отсылать данные небольшими кусочками, накапливаем
		// их сперва в один буфер.
		fmt::memory_buffer out_data;

		// Первой должна быть start-line.
		// Всегда отсылаем исходящие запросы как HTTP/1.1
		fmt::format_to(
				out_data,
				"{} {} HTTP/1.1\r\n",
				http_method_str(request_info.m_method),
				request_info.m_request_target );

		// Далее должен быть заголовок Host.
		fmt::format_to(
				out_data,
				"Host: {}\r\n",
				m_brief_request_info.m_host_field_value );

		// Переносим в исходящий запрос те заголовки, которые могут
		// уйти на удаленный узел.
		fill_headers_for_outgoing_request( can_throw, request_info, out_data );

		// Все, заголовки закончились.
		fmt::format_to( out_data, "\r\n" );

		m_user_end.m_pieces_read.push_back( std::move(out_data) );

		try_complete_parsing_of_initial_user_end_data( can_throw );
	}

	static void
	fill_headers_for_outgoing_request(
		can_throw_t /*can_throw*/,
		const request_info_t & request_info,
		// Подлежащие отсылки данные должны добавляться вот сюда.
		fmt::memory_buffer & out_data )
	{
		// Учитываем тот факт, что из заголовков уже поудаляли всю
		// информацию, которая не должна покидать прокси.
		// Так что все оставшиеся заголовки просто переносим как есть.
		request_info.m_headers.for_each_field(
			[&]( const auto & field )
			{
				fmt::format_to(
						out_data,
						"{}: {}\r\n", field.name(), field.value() );
			} );
	}

	void
	try_complete_parsing_of_initial_user_end_data(
		can_throw_t /*can_throw*/ )
	{
		http_handling_state_t & http_state = *(m_user_end.m_http_state);

		// Произведем разбор того, что есть во входящем буфере.
		const auto bytes_to_parse = http_state.m_incoming_data_size
				- http_state.m_next_execute_position;
		if( !bytes_to_parse )
			return;

		const auto bytes_parsed = http_parser_execute(
				&(http_state.m_parser),
				&(m_user_end.m_http_parser_settings),
				&(http_state.m_incoming_data.at(
					http_state.m_next_execute_position)),
				bytes_to_parse );
		http_state.m_next_execute_position += bytes_parsed;

		// Разберемся с результатом разбора.
		if( const auto err = http_state.m_parser.http_errno;
				HPE_OK != err && HPE_PAUSED != err )
			throw acl_handler_ex_t{
					fmt::format( "unexpected error during parsing of "
							"remaining part of incoming request, errno: {}",
							static_cast<unsigned>(http_state.m_parser.http_errno) )
				};

		// NOTE: изначально здесь была проверка на то, что все данные из
		// входящего буфера были полностью разобраны.
		// Но затем эта проверка была удалена. Потому, что если разбор
		// в user_end__on_message_complete ставится на паузу, то это
		// позволяет обрабатывать request pipelining. И в этом случае
		// часть данных во входящем буфере может остаться неразобранной.
		// Если же разбор на паузу в user_end__on_message_complete не
		// ставится (т.е. request pipelining не поддерживается), то
		// нет смысла проверять остаток данных. Поскольку либо этого
		// остатка нет, либо же парсер сломается на начале следующего
		// HTTP сообщения (из-за кода ошибки в user_end__on_message_begin).
	}

	// Обработчик завершения записи данных из user_end.
	void
	user_end_default_write_completed_handler(
		delete_protector_t /*delete_protector*/,
		can_throw_t can_throw )
	{
		// Если исходный запрос еще не был полностью вычитан из канала,
		// то нужно продолжать чтение.
		if( incoming_http_message_stage_t::in_progress ==
				m_user_end.m_incoming_message_stage )
		{
			initiate_async_read_for_direction( can_throw, m_user_end );
		}
	}

	// Дефолтный обработчик завершения записи данных из target_end.
	void
	target_end_default_write_completed_handler(
		delete_protector_t /*delete_protector*/,
		can_throw_t can_throw )
	{
		// Этот обработчик используется только пока HTTP-response не
		// прочитан полностью. Поэтому все, что нам здесь нужно сделать --
		// это инициировать следующее чтение.
		initiate_async_read_for_direction( can_throw, m_target_end );
	}

	// Обработчик завершения записи данных из target_end, который
	// используется для завершения записи HTTP-response и перехода
	// к нормальной процедуре завершения обработки входящего запроса.
	void
	target_end_normal_finilization_write_completed_handler(
		delete_protector_t delete_protector,
		can_throw_t can_throw)
	{
		// Если не нужно сохранять соединение с клиентом, то просто
		// удаляем текущий обработчик.
		// А вот если нужно сохранять соединение, то создаем новый
		// initial_http_handler.
		if( m_brief_request_info.m_keep_user_end_alive )
		{
			// Разберемся с тем, осталось ли что-нибудь во входящих данных.
			byte_sequence_t remaining_data;
			if( const auto & state = *(m_user_end.m_http_state);
					state.m_incoming_data_size > state.m_next_execute_position )
			{
				// Что-то осталось.
				remaining_data = byte_sequence_t{
						reinterpret_cast<const std::byte *>(
								&(state.m_incoming_data[ state.m_next_execute_position ]) ),
						state.m_incoming_data_size - state.m_next_execute_position
					};
			}

			replace_handler(
					delete_protector,
					can_throw,
					[this, &remaining_data]( can_throw_t )
					{
						return make_http_handler(
								std::move(m_ctx),
								m_id,
								std::move(m_connection),
								// В качестве первоначального значения отдаем все,
								// что осталось неразобранным в user_end.
								remaining_data,
								std::chrono::steady_clock::now() );
					} );
		}
		else
		{
			remove_handler(
					delete_protector,
					remove_reason_t::normal_completion );
		}
	}

	// Обработчик завершения записи данных из target_end, который
	// используется для завершения записи HTTP-response и последующего
	// принудительно удаления handler-а.
	void
	target_end_destroy_handler_write_completed_handler(
		delete_protector_t delete_protector,
		can_throw_t )
	{
		// Нам остается только удалить текущий обработчик.
		remove_handler(
				delete_protector,
				remove_reason_t::http_response_before_completion_of_http_request );
	}

	int
	user_end__on_message_begin( can_throw_t can_throw )
	{
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							"unexpected case: new message is found in data stream "
							"from client" );
				} );

		return -1;
	}

	int
	user_end__on_url( can_throw_t can_throw,
		const char *,
		std::size_t )
	{
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							"unexpected case: URL is found in data stream "
							"from client" );
				} );

		return -1;
	}

	int
	user_end__on_status( can_throw_t can_throw,
		const char *,
		std::size_t )
	{
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							"unexpected case: status-line is found in data "
							"stream from client" );
				} );

		return -1;
	}

	int
	user_end__on_header_field( can_throw_t /*can_throw*/,
		const char *,
		std::size_t )
	{
		// Это может быть только trailing-заголовок в chunked encoding.
		// Поскольку мы сейчас trailing-заголовки не поддерживаем, то
		// просто игнорируем его.
		return 0;
	}

	int
	user_end__on_header_value( can_throw_t /*can_throw*/,
		const char *,
		std::size_t )
	{
		// Это может быть только trailing-заголовок в chunked encoding.
		// Поскольку мы сейчас trailing-заголовки не поддерживаем, то
		// просто игнорируем его.
		return 0;
	}

	int
	user_end__on_headers_complete( can_throw_t can_throw )
	{
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							"unexpected case: repeated call of "
							"on_headers_complete callback" );
				} );

		return -1;
	}

	int
	user_end__on_body( can_throw_t /*can_throw*/,
		const char * data,
		std::size_t size )
	{
		// Нужно дописать очередной кусочек данных из входящего запроса.
		m_user_end.m_pieces_read.push_back( 
				// Безопасно сохранять string_view, т.к. сами данные,
				// на которые ссылается string_view, все еще находятся
				// во входящем буфере, который сохранит свое значение
				// до тех пор, пока все исходящие данные не будут
				// записаны.
				std::string_view{ data, size } );

		return 0;
	}

	int
	user_end__on_message_complete( can_throw_t /*can_throw*/ )
	{
		m_user_end.m_incoming_message_stage =
				incoming_http_message_stage_t::message_completed;

		// Приостанавливаем разбор данных из этого направления.
		// Есть подозренение, что такой подход поможет при обработке
		// request pipelining.
		http_parser_pause( &(m_user_end.m_http_state->m_parser), 1 );

		return 0;
	}

	int
	user_end__on_chunk_header( can_throw_t /*can_throw*/ )
	{
		// На момент вызова этого метода в http_parser.content_length
		// хранится длина очередного chunk-а. Используем это для того,
		// чтобы сформировать заголовок для идущего от target-end
		// chunk-а самостоятельно.
		m_user_end.m_pieces_read.push_back(
				fmt::format( "{:x}\r\n",
						m_user_end.m_http_state->m_parser.content_length ) );

		return 0;
	}

	int
	user_end__on_chunk_complete( can_throw_t /*can_throw*/ )
	{
		m_user_end.m_pieces_read.push_back( std::string_view{ "\r\n" } );

		return 0;
	}

	int
	target_end__on_message_begin( can_throw_t /*can_throw*/ )
	{
		// Здесь ничего не нужно делать!
		return 0;
	}

	int
	target_end__on_url( can_throw_t can_throw,
		const char *,
		std::size_t )
	{
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::err,
				[this, can_throw]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							"unexpected case: URL extracted from HTTP "
							"response (when HTTP status is expected" );
				} );

		return -1;
	}

	int
	target_end__on_status( can_throw_t can_throw,
		const char * data,
		std::size_t size )
	{
		const std::string_view reason_phrase{ data, size };

		// Строка со статусом может приходить по частям. Поэтому нужно сперва
		// понять, на какой стадии мы оказались.
		switch( m_response_processing_state.m_status_line_stage )
		{
		case status_line_processing_stage_t::not_started:
			// Нужно формировать начало status-line.
			m_response_processing_state.m_status_line =
					fmt::format( "HTTP/1.1 {} {}",
							static_cast<unsigned short>(
									m_target_end.m_http_state->m_parser.status_code),
							reason_phrase );
			m_response_processing_state.m_status_line_stage =
					status_line_processing_stage_t::status_code_written;

			// Такое логирование существенно упрощает разбирательство с
			// проблемами по логам.
			::arataga::logging::wrap_logging(
					proxy_logging_mode,
					spdlog::level::info,
					[this, can_throw, &reason_phrase]( auto level )
					{
						log_message_for_connection(
								can_throw,
								level,
								fmt::format( "incoming-reply=HTTP/{}.{} {} {}",
										m_target_end.m_http_state->m_parser.http_major,
										m_target_end.m_http_state->m_parser.http_minor,
										static_cast<unsigned short>(
												m_target_end.m_http_state->m_parser.status_code),
										::arataga::utils::subview_of<100>( reason_phrase )
								)
							);
					} );
		break;

		case status_line_processing_stage_t::status_code_written:
			m_response_processing_state.m_status_line += reason_phrase;
		break;

		case status_line_processing_stage_t::completed:
			// Этого не должно быть!
			throw acl_handler_ex_t{
					fmt::format( "target_end__on_status called when "
							"status-line is already completed" )
				};
		}

		// Строка состояния должна укладываться в заданный лимит.
		if( const auto lim =
				context().config().http_message_limits().m_max_status_line_length;
				lim < m_response_processing_state.m_status_line.size() )
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
										"status-line exceeds limit: size={}, limit={}",
										m_response_processing_state.m_status_line.size(),
										lim )
							);
					} );

			return -1;
		}

		return 0;
	}

	int
	target_end__on_header_field( can_throw_t can_throw,
		const char * data,
		std::size_t size )
	{
		if( m_response_processing_state.m_leading_headers_completed )
		{
			// Имеем дело с trailing-заголовками, которые мы пока игнорируем.
			return 0;
		}

		if( const auto rc = try_complete_response_last_header( can_throw );
				0 != rc )
		{
			return rc;
		}

		m_response_processing_state.m_last_header_name.append( data, size );

		// Длина имени заголовка не должна превышать разрешенный предел.
		if( const auto lim =
				context().config().http_message_limits().m_max_field_name_length;
				lim < m_response_processing_state.m_last_header_name.size() )
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
										"http-field name exceeds limit: size={}, "
										"limit={}",
										m_response_processing_state
											.m_last_header_name.size(),
										lim )
							);
					} );

			return -1;
		}

		return 0;
	}

	int
	target_end__on_header_value( can_throw_t can_throw,
		const char * data,
		std::size_t size )
	{
		if( m_response_processing_state.m_leading_headers_completed )
		{
			// Имеем дело с trailing-заголовками, которые мы пока игнорируем.
			return 0;
		}

		m_response_processing_state.m_on_header_value_called = true;
		m_response_processing_state.m_last_header_value.append( data, size );

		// Длина значения заголовка не должна превышать разрешенный предел.
		if( const auto lim =
				context().config().http_message_limits().m_max_field_value_length;
				lim < m_response_processing_state.m_last_header_value.size() )
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
										"http-field value exceeds limit: size={}, "
										"limit={}",
										m_response_processing_state
											.m_last_header_value.size(),
										lim )
							);
					} );

			return -1;
		}

		return 0;
	}

	void
	handle_connection_header_for_response( can_throw_t /*can_throw*/ )
	{
		using namespace restinio::http_field_parsers;

		constexpr std::string_view header_name{ "Connection" };

		auto & headers = m_response_processing_state.m_headers;

		// Сперва соберем значения из всех заголовков Connection
		// в одно место.
		connection_value_t aggregated;
		headers.for_each_value_of(
				header_name,
				[&]( const auto field_value ) {
					const auto r = connection_value_t::try_parse( field_value );
					if( r )
					{
						std::move( r->values.begin(), r->values.end(),
								std::back_inserter( aggregated.values ) );
					}

					// Ошибки просто игнорируем.
					return restinio::http_header_fields_t::continue_enumeration();
				} );

		// Теперь осталось пройтись по полученным значениям и обработать
		// их должным образом.
		for( const auto & v : aggregated.values )
		{
			// У значения "close" в Connection специальный смысл.
			// А вот все остальное должно восприниматься как имена
			// заголовков, подлежащих удалению.
			if( "close" != v )
			{
				// Заголовок Transfer-Encoding нужно оставить, т.к.
				// мы не производим трансформацию содержимого тела запроса,
				// а отдаем на целевой узел все именно так, как оно пришло
				// от клиента.
				if( "transfer-encoding" != v )
					headers.remove_all_of( v );
			}
		}

		// Заголовок Connection так же нужно удалить.
		headers.remove_all_of( header_name );
	}

	void
	remove_hop_by_hop_headers_from_response( can_throw_t /*can_throw*/ )
	{
		// Выбрасываем заголовки, которые являются hop-to-hop
		// заголовками и не должны уходить из прокси на целевой узел.
		//
		// ПРИМЕЧАНИЕ: выбрасываем не все заголовки. Так, оставляем
		// следующие заголовки:
		// - Transfer-Encoding, т.к. мы отдаем содержимое именно в том
		// виде, в котором получаем от клиента.
		//
		// Перечень hop-to-hop заголовков найден здесь:
		// https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection
		using namespace std::string_view_literals;
		static constexpr std::initializer_list< std::string_view >
			hop_by_hop_headers{
					"Keep-Alive"sv, "TE"sv, "Trailer"sv, "Proxy-Authentificate"sv
			};

		for( const auto & h : hop_by_hop_headers )
			m_response_processing_state.m_headers.remove_all_of( h );
	}

	void
	concat_response_headers_to(
		can_throw_t /*can_throw*/,
		fmt::memory_buffer & out_data )
	{
		const auto & headers = m_response_processing_state.m_headers;
		headers.for_each_field( [&out_data]( const auto & field ) {
				fmt::format_to(
						out_data,
						"{}: {}\r\n",
						field.name(),
						field.value() );
			} );
	}

	int
	target_end__on_headers_complete( can_throw_t can_throw )
	{
		// Отмечаем, что начальные заголовки закончились для того,
		// чтобы можно было игнорировать trailing-заголовки.
		m_response_processing_state.m_leading_headers_completed = true;

		if( const auto rc = try_complete_response_last_header( can_throw );
				0 != rc )
		{
			return rc;
		}

		// Для того, чтобы не отсылать все, что накопилось разобранного
		// из ответа маленькими частями, соберем все это в один буфер,
		// который будет отослан единовременно.
		fmt::memory_buffer out_data;

		complete_and_write_status_line( out_data );

		handle_connection_header_for_response( can_throw );
		remove_hop_by_hop_headers_from_response( can_throw );
		concat_response_headers_to( can_throw, out_data );

		// Далее должен идти "\r\n" для отделения заголовка от тела сообщения.
		fmt::format_to( out_data, "\r\n" );

		// Осталось отослать все, что было накоплено, одним куском.
		m_target_end.m_pieces_read.push_back( std::move( out_data ) );

		return 0;
	}

	int
	target_end__on_body( can_throw_t /*can_throw*/,
		const char * data,
		std::size_t size )
	{
		// Нужно дописать очередной кусочек body.
		m_target_end.m_pieces_read.push_back( 
				// Безопасно сохранять string_view, т.к. сами данные,
				// на которые ссылается string_view, все еще находятся
				// во входящем буфере, который сохранит свое значение
				// до тех пор, пока все исходящие данные не будут
				// записаны.
				std::string_view{ data, size } );

		return 0;
	}

	int
	target_end__on_message_complete( can_throw_t /*can_throw*/ )
	{
		m_target_end.m_incoming_message_stage =
				incoming_http_message_stage_t::message_completed;

		// Разбор на паузу здесь не ставим. Т.к. от target_end больше
		// ничего и не должно быть.

		return 0;
	}

	int
	target_end__on_chunk_header( can_throw_t /*can_throw*/ )
	{
		// На момент вызова этого метода в http_parser.content_length
		// хранится длина очередного chunk-а. Используем это для того,
		// чтобы сформировать заголовок для идущего от target-end
		// chunk-а самостоятельно.
		m_target_end.m_pieces_read.push_back(
				fmt::format( "{:x}\r\n",
						m_target_end.m_http_state->m_parser.content_length ) );
		return 0;
	}

	int
	target_end__on_chunk_complete( can_throw_t /*can_throw*/ )
	{
		m_target_end.m_pieces_read.push_back( std::string_view{ "\r\n" } );

		return 0;
	}

	// Смысл возвращаемого значения такой же, как и в callback-ах
	// для http_parser.
	[[nodiscard]]
	int
	try_complete_response_last_header( can_throw_t can_throw )
	{
		if( m_response_processing_state.m_on_header_value_called )
		{
			m_response_processing_state.m_total_headers_size +=
					m_response_processing_state.m_last_header_name.size() +
					m_response_processing_state.m_last_header_value.size();

			if( const auto lim =
					context().config().http_message_limits().m_max_total_headers_size;
					lim < m_response_processing_state.m_total_headers_size )
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
											m_response_processing_state
												.m_total_headers_size,
											lim )
								);
						} );

				return -1;
			}

			m_response_processing_state.m_headers.add_field(
					std::move(m_response_processing_state.m_last_header_name),
					std::move(m_response_processing_state.m_last_header_value) );

			m_response_processing_state.m_last_header_name.clear();
			m_response_processing_state.m_last_header_value.clear();
			m_response_processing_state.m_on_header_value_called = false;
		}

		return 0;
	}

	void
	complete_and_write_status_line( fmt::memory_buffer & out_data )
	{
		if( status_line_processing_stage_t::completed !=
				m_response_processing_state.m_status_line_stage )
		{
			fmt::format_to( out_data, "{}\r\n", 
					m_response_processing_state.m_status_line );

			m_response_processing_state.m_status_line.clear();
			m_response_processing_state.m_status_line_stage =
					status_line_processing_stage_t::completed;
		}
	}

	void
	try_parse_data_read(
		delete_protector_t delete_protector,
		can_throw_t can_throw,
		direction_state_t & src_dir )
	{
		// Произведем разбор того, что есть во входящем буфере.
		const auto bytes_to_parse = src_dir.m_http_state->m_incoming_data_size
				- src_dir.m_http_state->m_next_execute_position;

		const auto bytes_parsed = http_parser_execute(
				&(src_dir.m_http_state->m_parser),
				&(src_dir.m_http_parser_settings),
				&(src_dir.m_http_state->m_incoming_data.at(
					src_dir.m_http_state->m_next_execute_position)),
				bytes_to_parse );
		src_dir.m_http_state->m_next_execute_position += bytes_parsed;

		// Разберемся с результатом разбора.
		if( const auto err = src_dir.m_http_state->m_parser.http_errno;
				HPE_OK != err && HPE_PAUSED != err )
		{
			// Поведение при обнаружении каких-то проблем с HTTP-сообщением
			// зависит от того, из какого именно потока мы читали данные и
			// сколько успели записать в противоположном направлении.
			return react_to_direction_failure(
					delete_protector,
					can_throw,
					src_dir,
					remove_reason_t::protocol_error );
		}

		// Обрабатывать результат разбора прочитанных данных нужно
		// с учетом того, из какого направления данные были прочитаны.
		switch( src_dir.m_traffic_direction )
		{
		case traffic_limiter_t::direction_t::from_user:
			analyze_incoming_data_parsing_result_for_user_end( can_throw );
		break;

		case traffic_limiter_t::direction_t::from_target:
			analyze_incoming_data_parsing_result_for_target_end( can_throw );
		break;
		}
	}

	void
	react_to_direction_failure(
		delete_protector_t delete_protector,
		can_throw_t can_throw,
		const direction_state_t & src_dir,
		remove_reason_t remove_reason )
	{
		// Ситуацию с проблемой направления от целевого узла нужно
		// обрабатывать особым образом: если ничего не успели отослать
		// клиенту, то следует отослать 502 Bad Gateway.
		if( traffic_limiter_t::direction_t::from_target ==
				src_dir.m_traffic_direction )
		{
			if( 0u == m_user_end.m_bytes_from_opposite_dir )
			{
				return send_negative_response_then_close_connection(
						delete_protector,
						can_throw,
						remove_reason,
						response_bad_gateway_invalid_response );
			}
		}

		// В остальных случаях просто закрываем все.
		// Т.к. либо мусор получен от клиента, либо мусор получен от
		// целевого узла но уже после того, как часть ответа уже была
		// отослана клиенту.
		return remove_handler( delete_protector, remove_reason );
	}

	void
	analyze_incoming_data_parsing_result_for_user_end(
		can_throw_t can_throw )
	{
		// По сути, мы оказываемся в ситуации, когда все зависит от
		// состояния HTTP-response. Если HTTP-response еще не был
		// прочитан, то можно отсылать исходящие данные в target_end.
		// Но если HTTP-response уже был прочитан, то ничего делать
		// не нужно, т.к. нам остается только дождаться завершения
		// записи HTTP-response и удаления текущего handler-а.
		switch( m_target_end.m_incoming_message_stage )
		{
		case incoming_http_message_stage_t::in_progress:
			// HTTP-response еще не был полностью прочитан, так
			// что можно просто передавать очередную часть
			// HTTP-request-а на сторону целевого узла.
			initiate_write_outgoing_data_or_read_next_incoming_portion(
					can_throw, m_user_end, m_target_end );
		break;

		case incoming_http_message_stage_t::message_completed:
			// Ничего не нужно делать, т.к. нам остается только
			// дождаться завершения записи HTTP-response и удаления
			// handler-а.
		break;
		}
	}

	void
	analyze_incoming_data_parsing_result_for_target_end(
		can_throw_t can_throw )
	{
		// Записывать кусок HTTP-response нужно в любом случае.
		// Вопрос лишь в том, следует ли менять on_write_completed обработчик.
		switch( m_target_end.m_incoming_message_stage )
		{
		case incoming_http_message_stage_t::in_progress:
			/* Ничего менять не нужно */
		break;

		case incoming_http_message_stage_t::message_completed:
			// А вот здесь мы уже зависим от того, был ли прочитан
			// HTTP-запрос или нет. Если еще не был, то после записи
			// HTTP-response нужно будет удалять handler.
			switch( m_user_end.m_incoming_message_stage )
			{
			case incoming_http_message_stage_t::in_progress:
				m_target_end.m_on_write_completed =
					&ordinary_method_handler_t::
							target_end_destroy_handler_write_completed_handler;
			break;

			case incoming_http_message_stage_t::message_completed:
				m_target_end.m_on_write_completed =
					&ordinary_method_handler_t::
							target_end_normal_finilization_write_completed_handler;
			}
		break;
		}

		// Собственно, сама запись очередного куска HTTP-response.
		initiate_write_outgoing_data_or_read_next_incoming_portion(
				can_throw, m_target_end, m_user_end );
	}

	void
	initiate_write_outgoing_data_or_read_next_incoming_portion(
		can_throw_t can_throw,
		direction_state_t & src_dir,
		direction_state_t & dest_dir )
	{
		if( src_dir.m_pieces_read.empty() )
		{
			// Пока исходящих данных не появилось. Продолжаем читать
			// из входящего направления.
			initiate_async_read_for_direction( can_throw, src_dir );
		}
		else
		{
			write_data_read_from( can_throw, src_dir, dest_dir );
		}
	}

	// Этот метод не должен вызываться, если src_dir.m_pieces_read пуст.
	void
	write_data_read_from(
		can_throw_t /*can_throw*/,
		direction_state_t & src_dir,
		direction_state_t & dest_dir )
	{
		if( src_dir.m_pieces_read.empty() )
			// Записывать нечего. Такого не должно быть!
			throw acl_handler_ex_t{
					"a call to write_data_read_from for "
					"empty src_dir.m_pieces_read"
			};

		auto & piece_to_send = src_dir.m_pieces_read.front();

		// Пытаемся понять, сколько данных для отсылки мы сможем взять,
		// чтобы не превысить лимит.
		const auto reserved_capacity = m_traffic_limiter->reserve_read_portion(
				src_dir.m_traffic_direction,
				piece_to_send.remaining() );

		// Если ничего не можем отослать, значит превышен лимит.
		src_dir.m_is_traffic_limit_exceeded =
				( 0u == reserved_capacity.m_capacity );

		if( src_dir.m_is_traffic_limit_exceeded )
			// Нужно ждать наступления следующего такта.
			return;

		asio::const_buffer data_to_write{
				piece_to_send.asio_buffer().data(),
				reserved_capacity.m_capacity
		};

		// Нам нужно зафиксировать, сколько байт мы отошлем в dest_dir.
		// Затем эта информация может использоваться для определения того,
		// отсылалось ли dest_dir что-либо вообще или нет.
		dest_dir.m_bytes_from_opposite_dir += data_to_write.size();

// Этот фрагмент кода оставлен здесь в закомментированном виде для того,
// чтобы проще было вернуть его при необходимости отладки.
#if 0
		std::cout << "*** ougoing data: '"
				<< std::string_view{
							reinterpret_cast<const char *>(data_to_write.data()),
							data_to_write.size()
						}
				<< std::endl;
#endif

		asio::async_write(
				dest_dir.m_channel,
				data_to_write,
				with<const asio::error_code &, std::size_t>().make_handler(
					[this, &src_dir, &dest_dir, reserved_capacity](
						delete_protector_t delete_protector,
						can_throw_t can_throw,
						const asio::error_code & ec, std::size_t bytes )
					{
						reserved_capacity.release(
								*m_traffic_limiter,
								src_dir.m_traffic_direction,
								ec,
								bytes );

						on_write_result(
								delete_protector,
								can_throw,
								src_dir, dest_dir,
								ec,
								bytes );
					} )
			);
	}

	void
	initiate_async_read_for_direction(
		can_throw_t /*can_throw*/,
		// Откуда данные нужно читать.
		direction_state_t & src_dir )
	{
		auto buffer = asio::buffer(
				&(src_dir.m_http_state->m_incoming_data[0]),
				src_dir.m_http_state->m_incoming_data.size() );

		src_dir.m_channel.async_read_some(
				buffer,
				with<const asio::error_code &, std::size_t>().make_handler(
					[this, &src_dir](
						delete_protector_t delete_protector,
						can_throw_t can_throw,
						const asio::error_code & ec, std::size_t bytes )
					{
						on_read_result(
								delete_protector,
								can_throw,
								src_dir,
								ec,
								bytes );
					} )
			);
	}

	[[nodiscard]]
	remove_reason_t
	detect_remove_reason_from_read_result_error_code(
		can_throw_t can_throw,
		direction_state_t & src_dir,
		const asio::error_code & ec )
	{
		/*
		 * Особенность текущей логики обработки HTTP-сообщений в том,
		 * что как только HTTP-сообщение полностью вычитывается (т.е. для
		 * него отрабатывает message_complete-коллбэк), то чтение из
		 * соответствующего направления прекращается. Соответственно,
		 * если возникает EOF до того, как HTTP-сообщение было полностью
		 * вычитано, то это так же ненормальное завершение обслуживания
		 * запроса клиента. Вне зависимости от того, какое именно
		 * направление было закрыто.
		 */

		// Какой бы не была ошибка, соединение считается закрытым.
		src_dir.m_is_alive = false;

		auto remove_reason = remove_reason_t::unexpected_and_unsupported_case;

		if( asio::error::eof == ec )
		{
			// Дальнейшие действия зависят от того, что за соединение закрылось.
			if( traffic_limiter_t::direction_t::from_target ==
					src_dir.m_traffic_direction )
				remove_reason = remove_reason_t::target_end_broken;
			else
				remove_reason = remove_reason_t::user_end_broken;
		}
		else if( asio::error::operation_aborted == ec )
		{
			// Вообще особо ничего делать не нужно.
			remove_reason = remove_reason_t::current_operation_canceled;
		}
		else
		{
			// Возможно, мы наткнулись на ошибку ввода-вывода.
			// Но, может быть просто сейчас завершается наша работа и
			// сокет был закрыт, а Asio выдал код ошибки, отличный
			// от operation_aborted.
			if( src_dir.m_channel.is_open() )
			{
				// Все-таки это ошибка ввода-вывода.

				// Залогируем ошибку.
				::arataga::logging::wrap_logging(
						proxy_logging_mode,
						spdlog::level::debug,
						[this, can_throw, &src_dir, &ec]( auto level )
						{
							log_message_for_connection(
									can_throw,
									level,
									fmt::format( "error reading data from {}: {}",
											src_dir.m_name,
											ec.message() ) );
						} );

				remove_reason = remove_reason_t::io_error;
			}
			else
				remove_reason = remove_reason_t::current_operation_canceled;
		}

		return remove_reason;
	}

	/*!
	 * Обработка результатов чтения из src_dir.
	 *
	 * Есть два важных фактора, которые следует учитывать внутри on_read_result:
	 *
	 * 1. Если в @a ec содержится ошибка, то на значение @a bytes_transferred
	 * можно не обращать внимания. Т.к. даже если ошибка -- это eof, то
	 * все ранее вычитанные из src_dir данные были нами обработаны в
	 * предшествующем on_read_result, в котором в @a ec ошибки не было.
	 * Предполагать какую-то другую логику доставки eof нет оснований.
	 *
	 * 2. В src_dir на данный момент нет данных, которые еще не были
	 * отосланы в dest_dir. Ведь пока такие данные есть, новая операция
	 * чтения не инициируется вовсе.
	 *
	 */
	void
	on_read_result(
		delete_protector_t delete_protector,
		can_throw_t can_throw,
		direction_state_t & src_dir,
		const asio::error_code & ec,
		std::size_t bytes_transferred )
	{
#if 0
		// Этот код оставлен под комментарием для того, чтобы проще было
		// вернуть его при необрходимости отладки.
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::trace,
				[this, can_throw, &src_dir, ec, bytes_transferred]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							fmt::format( "on_read_result {}, ec: {}, bytes: {}",
									src_dir.m_name, ec.message(), bytes_transferred) );
				} );
#endif

		if( ec )
		{
			// В зависимости от того, какое направление сбойнуло и
			// что было прочитано из этого направления, нужно либо
			// сразу закрывать соединение, либо же отсылать клиенту
			// ответ 502 Bad Gateway.
			return react_to_direction_failure(
					delete_protector,
					can_throw,
					src_dir,
					detect_remove_reason_from_read_result_error_code(
							can_throw, src_dir, ec ) );
		}
		else
		{
			src_dir.m_http_state->m_incoming_data_size = bytes_transferred;
			src_dir.m_http_state->m_next_execute_position = 0u;

			// Должны зафиксировать время последней активности.
			m_last_read_at = std::chrono::steady_clock::now();

			// Осталось запустить разбор прочитанных данных, в процессе
			// чего будут сформированны кусочки исходящих данных.
			try_parse_data_read( delete_protector, can_throw, src_dir );
		}
	}

	void
	on_write_result(
		delete_protector_t delete_protector,
		can_throw_t can_throw,
		direction_state_t & src_dir,
		direction_state_t & dest_dir,
		const asio::error_code & ec,
		std::size_t bytes_transferred )
	{
		// При диагностировании ошибок записи просто прекращаем работу.
		if( ec )
		{
			log_and_remove_connection_on_io_error(
					delete_protector,
					can_throw, ec,
					fmt::format( "writting to {}", dest_dir.m_name ) );
		}
		else
		{
			if( src_dir.m_pieces_read.empty() )
				// Такого не должно быть. Ведь это результат записи
				// первого элемента из src_dir.m_pieces_read.
				throw acl_handler_ex_t{
					fmt::format( "on_write_result is called for "
							"empty {}.m_pieces_read",
							src_dir.m_name )
				};

			auto & piece_to_send = src_dir.m_pieces_read.front();
			piece_to_send.increment_bytes_written( bytes_transferred );
			if( !piece_to_send.remaining() )
				src_dir.m_pieces_read.pop_front();

			// Если есть еще что записывать, запишем и это.
			if( !src_dir.m_pieces_read.empty() )
				write_data_read_from( can_throw, src_dir, dest_dir );
			else
				// Все исходящие данные записаны, так что о дальнейшем
				// пусть заботится обработчик успешной записи.
				(this->*src_dir.m_on_write_completed)( delete_protector, can_throw );
		}
	}
};

//
// make_ordinary_method_handler
//
[[nodiscard]]
connection_handler_shptr_t
make_ordinary_method_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket in_connection,
	http_handling_state_unique_ptr_t http_state,
	request_info_t request_info,
	traffic_limiter_unique_ptr_t traffic_limiter,
	asio::ip::tcp::socket out_connection )
{
	return std::make_shared< ordinary_method_handler_t >(
			std::move(ctx),
			id,
			std::move(in_connection),
			std::move(http_state),
			std::move(request_info),
			std::move(traffic_limiter),
			std::move(out_connection) );
}

} /* namespace arataga::acl_handler */

} /* namespace handlers::http */

