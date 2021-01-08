/*!
 * @file
 * @brief Базовые вещи для реализации HTTP connection-handler-ов.
 */

#pragma once

#include <arataga/acl_handler/connection_handler_ifaces.hpp>
#include <arataga/acl_handler/buffers.hpp>

#include <arataga/acl_handler/exception.hpp>

#include <restinio/http_headers.hpp>

#include <nodejs/http_parser/http_parser.h>

#include <memory>
#include <vector>

namespace arataga::acl_handler
{

namespace handlers::http
{

/*!
 * @brief Объект для хранения информации для парсинга HTTP-сообщений.
 *
 * К этой информации относятся:
 *
 * - объект http_parser, который и производит парсинг;
 * - буфер с данными подлежащими разбору (в том числе и количество
 *   данных в этом буфере);
 * - позиция, с которой должна начинаться следующая попытка разбора.
 *
 * Предполагается, что объект данного типа будет создан при принятии
 * нового входящего соединения (или при создании нового исходящего
 * соединения), после чего будет сопровождать это соединение по мере
 * передачи его между connection-handler-ами.
 *
 * @note
 * В этом объекте есть http_parser, но нет http_parser_settings,
 * т.к. http_parser_settings зависит от connection-handler-а.
 * И каждый connection-handler, который будет обрабатывать
 * входящие HTTP-сообщения, будет создавать собственные экземпляры
 * http_parser_settings.
 */
struct http_handling_state_t
{
	http_parser m_parser;

	std::vector< char > m_incoming_data;
	std::size_t m_incoming_data_size;

	std::size_t m_next_execute_position{};

	http_handling_state_t( const http_handling_state_t & ) = delete;
	http_handling_state_t( http_handling_state_t && ) = delete;

	http_handling_state_t(
		std::size_t io_chunk_size,
		byte_sequence_t whole_first_pdu )
	{
		if( io_chunk_size < whole_first_pdu.size() )
			throw acl_handler_ex_t{
					fmt::format( "first PDU is too big ({} bytes) to fit "
							"into io_buffer ({} bytes)",
							whole_first_pdu.size(),
							io_chunk_size )
			};

		m_incoming_data.resize( io_chunk_size );
		std::transform(
				std::begin(whole_first_pdu),
				std::end(whole_first_pdu),
				std::begin(m_incoming_data),
				[]( std::byte b ) { return static_cast<char>(b); } );
		m_incoming_data_size = whole_first_pdu.size();

		http_parser_init( &m_parser, HTTP_REQUEST );
	}
};

/*!
 * @brief Псевдоним unique_ptr для http_handling_state.
 */
using http_handling_state_unique_ptr_t = std::unique_ptr<
		http_handling_state_t
	>;

/*!
 * @brief Тип объекта для хранения информации о входящем HTTP-запросе,
 * которая накапливается по мере разбора запроса.
 *
 * Объект типа http_handling_state_t хранит "сырую" информацию из
 * соединения, которая затем подвергается парсингу и обработке.
 * Результат этой обработки собирается в объекте request_info_t,
 * который создается при начале обработки очередного HTTP-запроса.
 */
struct request_info_t
{
	//! HTTP-метод для запроса.
	/*!
	 * Сохраняется в request_info для того, чтобы к нему было легко
	 * и удобно получать доступ.
	 */
	http_method m_method;

	//! Значение request-target из start-line.
	std::string m_request_target;

	//! Разобранные заголовки из входящего запроса.
	restinio::http_header_fields_t m_headers;

	//! Значение target_host для запроса.
	/*!
	 * Это значение извлекается либо из заголовка Host, либо из
	 * request-target.
	 */
	std::string m_target_host;
	//! Значение target_port для запроса.
	/*!
	 * Это значение извлекается либо из заголовка Host, либо из
	 * request-target.
	 */
	std::uint16_t m_target_port{ 80u };

	//! Нужно ли сохранять соединение с клиентом после обработки запроса.
	/*!
	 * Т.к. мы работаем по HTTP/1.1, то по умолчанию соединение нужно
	 * сохранять.
	 */
	bool m_keep_user_end_alive{ true };
};

//
// basic_http_handler_t
//
/*!
 * @brief Базовый класс для актуальных обработчиков HTTP-соединений.
 *
 * Содержит в себе методы, которые потребуются в одном и том же виде
 * остальным обработчикам.
 */
class basic_http_handler_t : public connection_handler_t
{
public:
	using connection_handler_t::connection_handler_t;

protected:
	// ПРИМЕЧАНИЕ! Заменяет текущий connection_handler новым
	// обработчиком, который и отсылает отрицательный ответ.
	void
	send_negative_response_then_close_connection(
			delete_protector_t delete_protector,
			can_throw_t can_throw,
			remove_reason_t reason,
			std::string_view whole_response );
};

//
// handler_with_out_connection_t
//
/*!
 * @brief Базовый класс для актуальных обработчиков HTTP-соединений
 * которые имеют еще и исходящее соединение.
 *
 * Содержит поле m_out_connection.
 *
 * Переопределяет метод release() для принудительного
 * закрытия m_out_connection.
 */
class handler_with_out_connection_t : public basic_http_handler_t
{
protected:
	//! Исходящее соединение.
	asio::ip::tcp::socket m_out_connection;

public:
	//! Конструктор для случая, когда исходящее соединение
	//! не нужно инициализировать конкретным сокетом.
	handler_with_out_connection_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket in_connection );

	//! Конструктор для случая, когда для исходящего соединения
	//! уже есть открытый сокет.
	handler_with_out_connection_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket in_connection,
		asio::ip::tcp::socket out_connection );
	
	void
	release() noexcept override;
};

} /* namespace arataga::acl_handler */

} /* namespace handlers::http */

