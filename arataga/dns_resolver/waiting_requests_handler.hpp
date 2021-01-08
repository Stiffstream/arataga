/*!
 * @file
 * @brief Вспомогательный класс для хранения информации о запросах
 * на разрешение доменного имени или адреса.
 */

#pragma once

#include <arataga/dns_resolver/pub.hpp>

#include <list>

namespace arataga::dns_resolver
{


/*!
 * @brief Класс, хранящий активные запросы на разрешение имени.
 *
 * Суть данного класса заключается в том, чтобы не делать реальные запросы
 * к DNS-серверу на каждый приходящий ResolveRequest из-за возможности появления
 * дублей запросов.
 *
 * В результате добавления очередного запроса возвращается флаг, указывающий на
 * необходимость совершения реального запроса к DNS-серверу.
 *
 * @tparam Key Тип ключа, по которому хранятся элементы в словаре.
 * @tparam ResolveRequest Тип запроса на разрешение имени.
 * @tparam ResolveResponse Тип ответа на запрос.
 */
template <
	typename Key,
	typename ResolveRequest,
	typename ResolveResponse >
class waiting_requests_handler_t
{
	using completion_token_t =
		typename ResolveResponse::completion_token_t;

	using resolve_result_t =
		typename ResolveResponse::resolve_result_t;

	//! Вспомогательная информация о запросе, чтобы в дальнейшем
	//! ее прокинуть в ответ.
	struct resolve_request_info_t
	{
		//! Идетификатор запроса.
		resolve_req_id_t m_req_id;

		//! В каком виде требуется представить ответ.
		ip_version_t m_ip_version;

		//! Токен для завершения обработки запроса.
		/*!
		* @note
		* Может быть нулевым указателем.
		*/
		completion_token_t m_completion_token;

		//! Mbox, на который нужно отправить ответ.
		so_5::mbox_t m_reply_to;
	};

public:

	/*!
	 * @brief Добавить запрос в список ожидающий.
	 *
	 * @param key Ключ, по которому определяется запрос.
	 * @param req Запрос на разрешение.
	 * @return true Если необходимо совершать реальный запрос.
	 * @return false Если запрос по такому ключу уже выполняется.
	 */
	[[nodiscard]]
	bool
	add_request( const Key & key, const ResolveRequest & req )
	{
		bool need_resolve = false;

		auto find = m_waiting_requests.find( key );

		if( find == m_waiting_requests.end() )
		{
			resolve_requests_info_list_t requests = {
			resolve_request_info_t {
				req.m_req_id,
				req.m_ip_version,
				req.m_completion_token,
				req.m_reply_to } };

			m_waiting_requests.emplace(
				key,
				std::move(requests) );

			need_resolve = true;
		}
		else
		{
			find->second.push_back(
				resolve_request_info_t {
					req.m_req_id,
					req.m_ip_version,
					req.m_completion_token,
					req.m_reply_to } );

			need_resolve = false;
		}

		return need_resolve;
	}

	/*!
	 * @brief Обработать результат разрешения для всех элементов по ключу.
	 * Для всех запросов устанавливается один результат. Может быть полезно,
	 * если от DNS-сервера пришел отрицательный результат разрешения имени.
	 *
	 * @param key Ключ, по которому хранится запрос в словаре.
	 * @param result Результаты разрешения имени или адреса, пришедшие от DNS-сервера.
	 * @param logger Функция для логирования результата.
	 */
	template<typename LoggerFunc>
	void
	handle_waiting_requests(
		const Key & key,
		const resolve_result_t & result,
		LoggerFunc && logger )
	{
		auto find = m_waiting_requests.find( key );

		if( find != m_waiting_requests.end() )
		{
			auto requests = std::move( find->second );
			m_waiting_requests.erase( find );

			for( const auto & req_info : requests )
			{
				so_5::send< ResolveResponse >(
					req_info.m_reply_to,
					req_info.m_req_id,
					req_info.m_completion_token,
					result );

				logger( std::move(req_info.m_req_id), result );
			}
		}
	}

	/*!
	 * @brief Обработать результаты разрешения для всех элементов по ключу.
	 *
	 * @param key Ключ, по которому хранится запрос в словаре.
	 * @param results Результаты разрешения имени, пришедшие от DNS-сервера.
	 * @param logger Функция для логирования результата.
	 * @param address_extractor Функция, позволяющая извлечь адрес из
	 * объекта-результата разрешения имени.
	 */
	template<typename List, typename LoggerFunc, typename Extractor>
	void
	handle_waiting_requests(
		const Key & key,
		const List & results,
		LoggerFunc && logger,
		Extractor && address_extractor )
	{
		auto find = m_waiting_requests.find( key );

		if( find != m_waiting_requests.end() )
		{
			auto requests = std::move( find->second );
			m_waiting_requests.erase( find );

			for( const auto & req_info : requests )
			{
				auto result = get_resolve_result(
					results, req_info.m_ip_version, address_extractor );

				so_5::send< ResolveResponse >(
					req_info.m_reply_to,
					req_info.m_req_id,
					req_info.m_completion_token,
					result );

				logger(
					std::move(req_info.m_req_id),
					std::move(result) );
			}
		}
	}

private:

	//! Тип списка элементов, хранящих информацию о запросе.
	using resolve_requests_info_list_t =
		std::list< resolve_request_info_t >;

	/*!
	 * @brief Словарь содержащий запросы к DNS-серверу.
	 *
	 * Ключ -- Элемент, по которому выполняется разрешение.
	 * В случае прямого разрешения это имя, в обратном случае - адрес.
	 *
	 * Значение -- Список запросов, запрашивающих ту же информацию.
	 *
	 */
	std::map< Key, resolve_requests_info_list_t > m_waiting_requests;

};

} /* namespace arataga::dns_resolver */
