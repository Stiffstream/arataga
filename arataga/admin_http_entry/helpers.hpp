/*!
 * @file
 * @brief Различные вспомогательные инструменты для работы с
 * административным HTTP-входом.
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
 * @brief Вспомогательная функция для синхронной обработки запроса
 * от административного HTTP-входа.
 *
 * Эта функция должна использоваться в случае, когда ответ на запрос
 * должен быть сформирован прямо во время обработки запроса.
 *
 * Саму обработку запроса должна выполнять лямбда-функция @a lambda.
 * 
 * Исключения, которые выпускает @a lambda наружу перехватываются.
 * В случае перехвата исключений автоматически формируется отрицательный
 * ответ на запрос.
 *
 * @tparam Lambda Тип лямбда-функции (функтора). Эта лямбда функция вызывается
 * внутри envelope_sync_request_handling и она должна возвратить ответ на
 * запрос.
 * Формат этой лямбда функции:
 * @code
 * replier_t::reply_params_t lambda();
 * @endcode
 */
template< typename Lambda >
void
envelope_sync_request_handling(
	//! Описание контекста, в котором происходит обработка запроса.
	//! Это описание затем будет использовано для выдачи отрицательного
	//! ответа в случае возникновения исключений.
	std::string_view context_description,
	//! Объект для отсылки ответа в HTTP-вход.
	replier_t & replier,
	//! Статус для отрицательного ответа, который будет использован
	//! при возникновении исключения.
	status_t failure_status,
	//! Лямбда-функция (функтор), которая и будет выполнять обработку запроса.
	Lambda && lambda )
{
	std::optional< replier_t::reply_params_t > reply_data;

	// Возникшие при выполнении этой операции исключения критичными
	// не считаем.
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

	// В принципе, не должно быть так, что в reply_data нет значения.
	// Но на всякий случай перестраховываемся.
	if( reply_data )
		replier.reply( std::move(*reply_data) );
	else
		replier.reply(
				status_internal_server_error,
				fmt::format( "{} doesn't provide "
						"a description of new_config handling result\r\n",
						context_description ) );
}

/*!
 * @brief Вспомогательная функция для асинхронной обработки запроса
 * от административного HTTP-входа.
 *
 * Эта функция должна использоваться в случае, когда ответ на запрос
 * не может быть сформирован прямо во время обработки запроса.
 * А будет получен и отослан в HTTP-вход когда-то в будущем, уже
 * после возврата из envelope_async_request_handling.
 *
 * Саму обработку запроса должна выполнять лямбда-функция @a lambda.
 * 
 * Исключения, которые выпускает @a lambda наружу перехватываются.
 * В случае перехвата исключений автоматически формируется отрицательный
 * ответ на запрос.
 *
 * @tparam Lambda Тип лямбда-функции (функтора). Эта лямбда функция
 * вызывается внутри envelope_async_request_handling.
 * Формат этой лямбда функции:
 * @code
 * void lambda();
 * @endcode
 */
template< typename Lambda >
void
envelope_async_request_handling(
	//! Описание контекста, в котором происходит обработка запроса.
	//! Это описание затем будет использовано для выдачи отрицательного
	//! ответа в случае возникновения исключений.
	std::string_view context_description,
	//! Объект для отсылки ответа в HTTP-вход.
	replier_t & replier,
	//! Статус для отрицательного ответа, который будет использован
	//! при возникновении исключения.
	status_t failure_status,
	//! Лямбда-функция (функтор), которая и будет выполнять обработку запроса.
	Lambda && lambda )
{
	std::optional< replier_t::reply_params_t > reply_data;

	// Возникшие при выполнении этой операции исключения критичными
	// не считаем.
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

