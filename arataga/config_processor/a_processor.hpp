/*!
 * @file
 * @brief Агент для обработки конфигурации.
 */

#pragma once

#include <arataga/config_processor/pub.hpp>
#include <arataga/authentificator/pub.hpp>
#include <arataga/dns_resolver/pub.hpp>

#include <arataga/config.hpp>

#include <so_5_extra/disp/asio_one_thread/pub.hpp>

namespace arataga::config_processor
{

//
// a_processor_t
//
/*!
 * @brief Агент для работы с конфигурацией arataga.
 */
class a_processor_t : public so_5::agent_t
{
public:
	//! Основной конструктор.
	a_processor_t(
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

	// Эта структура описана в публичной части для того, чтобы
	// с ней могли работать свободные вспомогательные функции,
	// не входящие в класс a_processor_t.

	//! Описание одного запущенного ACL.
	struct running_acl_info_t
	{
		//! Конфигурация для этого ACL.
		acl_config_t m_config;

		//! Порядковый номер IO-thread, к которой привязан данный ACL.
		std::size_t m_io_thread_index;

		//! Почтовый ящик, через который можно общаться с этим ACL.
		so_5::mbox_t m_mbox;

		//! Инициализирующий конструктор.
		running_acl_info_t(
			acl_config_t config,
			std::size_t io_thread_index,
			so_5::mbox_t mbox )
			:	m_config{ std::move(config) }
			,	m_io_thread_index{ io_thread_index }
			,	m_mbox{ std::move(mbox) }
		{}
	};

private:
	//! Описание одной IO-нити, на которой обслуживаются ACL.
	struct io_thread_info_t
	{
		//! Диспетчер, к которому должны привязываться агенты acl_handler.
		so_5::extra::disp::asio_one_thread::dispatcher_handle_t m_disp;

		//! Кооперация с агентом authentificator для этой IO-нити.
		so_5::coop_handle_t m_auth_coop;
		//! Почтовый ящик агента authentificator для этой IO-нити.
		so_5::mbox_t m_auth_mbox;

		//! Кооперация с агентом dns_resolver для этой IO-нити.
		so_5::coop_handle_t m_dns_coop;
		//! Почтовый ящик агента dns_resolver для этой IO-нити.
		so_5::mbox_t m_dns_mbox;

		//! Сколько ACL запущенно на этом диспетчере.
		std::size_t m_running_acl_count{ 0u };
	};

	//! Тип контейнера для хранения диспетчеров, к которым должны
	//! привязываться агенты acl_handler.
	using io_thread_container_t = std::vector< io_thread_info_t >;

	//! Тип контейнера для хранения информации о созданных ACL.
	using running_acl_container_t = std::vector< running_acl_info_t >;

	//! Контекст всего arataga.
	const application_context_t m_app_ctx;

	//! Индивидуальные параметры для агента.
	const params_t m_params;

	//! Имя файла с локальной копией конфига.
	const std::filesystem::path m_local_config_file_name;

	//! Парсер конфигурации.
	config_parser_t m_parser;

	//! Диспетчеры, которые должны обслуживать агентов acl_handler.
	/*!
	 * Изначально этот контейнер пуст. Диспетчеры создаются при первой
	 * успешной загрузке конфигурации.
	 */
	io_thread_container_t m_io_threads;

	//! Информация о запущенных ACL.
	/*!
	 * @attention
	 * Содержимое этого списка должно быть упорядочно по (port, in_addr).
	 */
	running_acl_container_t m_running_acls;

	//! Счетчик обновлений конфигурации.
	/*!
	 * Увеличивается каждый раз как поступает корректно разобранная
	 * и непротиворечивая версия конфигурации.
	 *
	 * Используется при формировании имен дочерних агентов.
	 */
	std::uint_fast64_t m_config_update_counter{ 0u };

	//! Реакция на получение новой конфигурации.
	void
	on_new_config(
		mhood_t< new_config_t > cmd );

	//! Реакция на запрос списка известных ACL.
	void
	on_get_acl_list(
		mhood_t< get_acl_list_t > cmd );

	//! Реакция на попытку провести тестовую аутентификацию.
	void
	on_debug_auth(
		mhood_t< debug_auth_t > cmd );

	//! Реакция на получение ответа на попытку провести
	//! тестовую аутентификацию.
	void
	on_auth_reply(
		mhood_t< ::arataga::authentificator::auth_reply_t > cmd );

	//! Реакция на запрос разрешения доменного имени.
	void
	on_debug_dns_resolve(
		mhood_t< debug_dns_resolve_t > cmd );

	//! Реакция на получение ответа о попытке разрешения доменного имени.
	void
	on_resolve_reply(
		mhood_t< ::arataga::dns_resolver::resolve_reply_t > cmd );

	void
	try_load_local_config_first_time();

	//! Попытка обработать новый конфиг, который пришел
	//! в виде POST-запроса от HTTP-входа.
	/*!
	 * В случае ошибок порождает исключение.
	 */
	void
	try_handle_new_config_from_post_request(
		std::string_view content );

	//! Попытка обработать конфиг, который только что был успешно
	//! разобран.
	/*!
	 * Этот метод должен вызываться после того, как конфиг был
	 * успешно разобран после чтения содержимого конфига из файла или
	 * после получения его от HTTP-входа.
	 */
	void
	try_handle_just_parsed_config(
		config_t config );

	/*!
	 * @attention
	 * Ожидается, что список ACL в @a config будет упорядочен
	 * по (port, in_addr) и что в нем не будет дубликатов.
	 *
	 * @note
	 * ПРИМЕЧАНИЕ: этот метод не выпускает наружу исключений. Если внутри
	 * возникает исключение, то оно логируется, а работа приложения аварийно
	 * прерывается.
	 */
	void
	accept_new_config( config_t config ) noexcept;

	void
	send_updated_config_messages(
		const config_t & config );

	/*!
	 * @attention
	 * Ожидается, что список ACL в @a config будет упорядочен
	 * по (port, in_addr) и что в нем не будет дубликатов.
	 */
	void
	handle_upcoming_acl_list(
		const config_t & config );

	void
	create_dispatchers_if_necessary(
		const config_t & config );

	/*!
	 * @attention
	 * Ожидается, что список ACL в @a config будет упорядочен
	 * по (port, in_addr) и что в нем не будет дубликатов.
	 */
	void
	stop_and_remove_outdated_acls(
		const config_t & config );

	/*!
	 * @attention
	 * Ожидается, что список ACL в @a config будет упорядочен
	 * по (port, in_addr) и что в нем не будет дубликатов.
	 *
	 * На выходе будет m_running_acls, в котором все ACL так
	 * же будут упорядочены по (port, in_addr).
	 */
	void
	launch_new_acls(
		const config_t & config );

	[[nodiscard]]
	std::size_t
	index_of_io_thread_with_lowest_acl_count() const noexcept;

	//! Сохранение нового конфига в локальный файл.
	/*!
	 * @note
	 * Возникшие при выполнении этой операции исключения логируются,
	 * но не выпускаются наружу.
	 */
	void
	store_new_config_to_file(
		std::string_view content );

	//! Начало обработки тестовой аутентификации пользователя.
	void
	initiate_debug_auth_processing(
		::arataga::admin_http_entry::replier_shptr_t replier,
		::arataga::admin_http_entry::debug_requests::authentificate_t request );

	//! Начало обработки запроса на разрешение доменного имени.
	void
	initiate_debug_dns_resolve_processing(
		::arataga::admin_http_entry::replier_shptr_t replier,
		::arataga::admin_http_entry::debug_requests::dns_resolve_t request );
};

} /* namespace arataga::config_processor */

