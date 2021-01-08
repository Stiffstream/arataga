/*!
 * @file
 * @brief Описание агента dns_resolver.
 */

#pragma once

#include <arataga/dns_resolver/pub.hpp>
#include <arataga/dns_resolver/waiting_requests_handler.hpp>
#include <arataga/config_processor/notifications.hpp>

#include <arataga/stats/dns/pub.hpp>

#include <asio/ip/tcp.hpp>

#include <map>
#include <chrono>
#include <list>

namespace arataga::dns_resolver
{

/*!
 * @brief Класс, определяющий локальный кеш с доменными именами.
 * Реализован в виде словаря, соотносящего имя ресурса к его адресу и времени
 * создания записи.
 */
class local_cache_t
{
public:
	local_cache_t() = default;
	~local_cache_t() = default;

	/*!
	 * @brief Выполнить разрешение доменного имени.
	 *
	 * @param name Имя, для которого нужно получить адрес.
	 * @return std::optional<asio::ip::address> Адрес из локального словаря
	 * или std::nullopt.
	 */
	[[nodiscard]]
	std::optional<asio::ip::address>
	resolve(
		const std::string & name,
		ip_version_t ip_version ) const;

	/*!
	 * @brief Удалить устаревшие записи.
	 *
	 * @param time_to_live Время жизни, старше которого элементы будут удалены.
	 *
	 * @return Количество элементов, которые были изъяты из кэша.
	 */
	std::size_t
	remove_outdated_records( const std::chrono::seconds & time_to_live );

	/*!
	 * @brief Добавить запись в словарь.
	 *
	 * @param name Имя ресурса.
	 * @param address Адрес ресурса.
	 */
	// void
	// add_record(
	// 	std::string name,
	// 	asio::ip::address address );

	void
	add_records(
		std::string name,
		const asio::ip::tcp::resolver::results_type & results );

	/*!
	 * @brief Очистить содержимое кеша.
	 */
	void
	clear();

	void dump( std::ostream & o ) const
	{
		o << "[";

		for( const auto & elem: m_data )
		{
			o << "{" << "{name " << elem.first << "}";
			o << "{age_sec " << elem.second.age().count() << "}";
			o << "[";

			for( const auto & addr: elem.second.m_addresses )
			{
				o << "{ip " << addr.to_string() << "}";
			}

			o << "]" << "}";
		}

		o << "]";
	}

private:

	/*!
	 * @brief Вспомогательный класс, объекты которого соотносятся
	 * к именам ресурсов в локальном кеше.
	 *
	 * Данный класс необходим для возможности хранения времени создания
	 * записи в кеше вместе с адресом ресурса для последующего удаления
	 * устаревших записей.
	 */
	struct resolve_info_t
	{
		asio::ip::address m_address;

		//! Адрес записи.
		std::list< asio::ip::address > m_addresses;

		//! Момент времени создания записи.
		std::chrono::steady_clock::time_point m_creation_time;

		resolve_info_t(
			asio::ip::address address,
			std::chrono::steady_clock::time_point creation_time )
			:	m_address{ std::move(address) }
			,	m_creation_time{ std::move(creation_time) }
		{
		}

		resolve_info_t(
			std::chrono::steady_clock::time_point creation_time )
			:	m_creation_time{ std::move(creation_time) }
		{
		}

		[[nodiscard]]
		std::chrono::seconds
		age() const
		{
			return
				std::chrono::duration_cast<std::chrono::seconds>(
					std::chrono::steady_clock::now() - m_creation_time );
		}

		/*!
		* @brief Проверить, устарела ли информация о разрешении имени.
		*
		* @param time_to_live Время жизни объекта.
		* @return true Если информация устарела.
		* @return false Если информация не устарела.
		*/
		[[nodiscard]]
		bool
		is_outdated( const std::chrono::seconds & time_to_live ) const
		{
			return age() >= time_to_live;
		}
	};
	/*!
	 * @brief Локальный словарь ресурсов, для которых ранее выполнялся резолвинг.
	 *
	 * Ключ - имя ресурса.
	 *
	 * Значение - информация о записи, содержащая адреса ресурса и время создания
	 * записи в локальном кеше.
	 */
	std::map< std::string, resolve_info_t > m_data;
};

inline std::ostream &
operator<<( std::ostream & o, const local_cache_t & cache )
{
	cache.dump(o);

	return o;
}

//
// a_dns_resolver_t
//
/*!
 * @brief Агент для работы с конфигурацией arataga.
 */
class a_dns_resolver_t final : public so_5::agent_t
{
public:
	//! Основной конструктор.
	a_dns_resolver_t(
		//! SOEnv и параметры для агента.
		context_t ctx,
		//! Контекст всего arataga.
		application_context_t app_ctx,
		//! Индивидуальные параметры для этого агента.
		params_t params );

	void
	so_define_agent() override;

	void
	so_evt_start() override;

	void
	so_evt_finish() override;

private:

	//! Сигнал о необходимости очистить кеш.
	struct clear_cache_t final : public so_5::signal_t {};

	//! Событие появления нового запроса на разрешение имени.
	void
	on_resolve( const resolve_request_t & msg );

	//! Событие очистки содержимого кеша.
	void
	on_clear_cache( so_5::mhood_t<clear_cache_t> );

	using updated_dns_params_t =
		arataga::config_processor::updated_dns_params_t;

	//! Реакция на обновление параметров конфигурации.
	void
	on_updated_dns_params(
		const updated_dns_params_t & msg );

	//! Обработать результат поиска.
	void
	handle_resolve_result(
		//! Код ошибки asio.
		const asio::error_code & ec,
		//! Результаты разрешения доменного имени.
		asio::ip::tcp::resolver::results_type results,
		std::string name );

	//! Контекст всего arataga.
	const application_context_t m_app_ctx;

	//! Индивидуальные параметры этого агента.
	const params_t m_params;

	//! Индивидуальная статистика этого агента.
	::arataga::stats::dns::dns_stats_t m_dns_stats;
	::arataga::stats::dns::auto_reg_t m_dns_stats_reg;

	//! Текущий темп очистки кэша от старых записей.
	std::chrono::milliseconds m_cache_cleanup_period;

	//! Экземпляр resolver-а из asio.
	asio::ip::tcp::resolver m_resolver;

	//! Локальный кеш.
	local_cache_t m_cache;

	/*!
	 * @brief Добавить запрос в список ожидающих и если в данный момент
	 * для этого имени нет обращения к DNS-серверу, то сделать соответствующий
	 * запрос.
	 *
	 * @param req Запрос на разрешение доменного имени.
	 */
	void
	add_to_waiting_and_resolve( const resolve_request_t & req );

	waiting_requests_handler_t<
		std::string,
		resolve_request_t,
		resolve_reply_t > m_waiting_forward_requests;
};

} /* namespace arataga::dns_resolver */

