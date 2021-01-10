/*!
 * @file
 * @brief Описание агента acl_handler.
 */

#pragma once

#include <arataga/acl_handler/pub.hpp>

#include <arataga/acl_handler/connection_handler_ifaces.hpp>

#include <arataga/acl_handler/bandlim_manager.hpp>

#include <arataga/stats/connections/pub.hpp>

#include <arataga/config_processor/notifications.hpp>

#include <arataga/dns_resolver/pub.hpp>

#include <arataga/authentificator/pub.hpp>

#include <arataga/one_second_timer.hpp>

#include <asio/ip/tcp.hpp>

namespace arataga::acl_handler
{

//
// actual_config_t
//
/*!
 * @brief Актуальная реализация интерфейса config.
 */
class actual_config_t final : public config_t
{
	const acl_config_t & m_acl_config;
	const common_acl_params_t & m_common_acl_params;

public:
	actual_config_t(
		const acl_config_t & acl_config,
		const common_acl_params_t & common_acl_params );

	[[nodiscard]]
	acl_protocol_t
	acl_protocol() const noexcept override;

	[[nodiscard]]
	const asio::ip::address &
	out_addr() const noexcept override;

	[[nodiscard]]
	std::size_t
	io_chunk_size() const noexcept override;

	[[nodiscard]]
	std::size_t
	io_chunk_count() const noexcept override;

	[[nodiscard]]
	std::chrono::milliseconds
	protocol_detection_timeout() const noexcept override;

	[[nodiscard]]
	std::chrono::milliseconds
	socks_handshake_phase_timeout() const noexcept override;

	[[nodiscard]]
	std::chrono::milliseconds
	dns_resolving_timeout() const noexcept override;

	[[nodiscard]]
	std::chrono::milliseconds
	authentification_timeout() const noexcept override;

	[[nodiscard]]
	std::chrono::milliseconds
	connect_target_timeout() const noexcept override;

	[[nodiscard]]
	std::chrono::milliseconds
	socks_bind_timeout() const noexcept override;

	[[nodiscard]]
	std::chrono::milliseconds
	idle_connection_timeout() const noexcept override;

	[[nodiscard]]
	std::chrono::milliseconds
	http_headers_complete_timeout() const noexcept override;

	[[nodiscard]]
	std::chrono::milliseconds
	http_negative_response_timeout() const noexcept override;

	[[nodiscard]]
	const http_message_value_limits_t &
	http_message_limits() const noexcept override;
};

//
// authentificated_user_info_t
//
//! Информация о клиенте, который успешно прошел аутентификацию.
struct authentificated_user_info_t
{
	//! Текущее количество подключений от данного клиента.
	std::size_t m_connection_count{};

	//! Лимиты для данного клиента.
	bandlim_manager_t m_bandlims;
};

//
// authentificated_user_map_t
//
//! Словарь успешно аутентифицированных пользователей.
using authentificated_user_map_t = std::map<
		::arataga::user_list_auth::user_id_t,
		authentificated_user_info_t
	>;

//
// a_handler_t
//
/*!
 * @brief Агент, который выполняет роль ACL.
 *
 * Примечание по поводу особенностей работы replace_connection_handler()
 * и remove_connection().
 *
 * Замена обработчиков соединений происходит в методе
 * replace_connection_handler(), который вызывается текущим
 * connection-handler-ом синхронно. При этом может оказаться,
 * что когда внутри replace_connection_handler() у нового
 * connection-handler-а вызывается on_start, то новый
 * connection-handler может вызвать у a_handler-а метод
 * replace_connection_handler() (чтобы заменить connection-handler
 * еще раз) или метод remove_connection() (чтобы удалить соединение,
 * если обслуживать его нельзя).
 *
 * Так же осторожность нужно проявлять при вызове on_timer у
 * connection_handler-ов, т.к. внутри on_timer может произойти
 * обратный вызов remove_connection() и a_handler-у потребуется
 * удалить тот connection-handler, для которого сейчас вызван
 * on_timer.
 */
class a_handler_t final
	:	public so_5::agent_t
	,	public handler_context_t
{
public:
	//! Основной конструктор.
	a_handler_t(
		context_t ctx,
		application_context_t app_ctx,
		params_t params );
	~a_handler_t() override;

	void
	so_define_agent() override;

	void
	so_evt_start() override;

	void
	so_evt_finish() override;

	void
	replace_connection_handler(
		delete_protector_t,
		connection_id_t id,
		connection_handler_shptr_t handler ) override;

	void
	remove_connection_handler(
		delete_protector_t,
		connection_id_t id,
		remove_reason_t reason ) noexcept override;

	void
	log_message_for_connection(
		connection_id_t id,
		::arataga::logging::processed_log_level_t level,
		std::string_view message ) override;

	[[nodiscard]]
	const config_t &
	config() const noexcept override;

	void
	async_resolve_hostname(
		connection_id_t connection_id,
		const std::string & hostname,
		dns_resolving::hostname_result_handler_t result_handler ) override;

	void
	async_authentificate(
		connection_id_t connection_id,
		authentification::request_params_t request,
		authentification::result_handler_t result_handler ) override;

	void
	stats_inc_connection_count(
		connection_type_t connection_type ) override;

private:
	//! Сигнал о необходимости предпринять попытку создания точки входа.
	struct try_create_entry_point_t final : public so_5::signal_t {};

	//! Сигнал о необходимости сделать очередной async_accept.
	struct accept_next_t final : public so_5::signal_t {};

	//! Сигнал о том, что очередной вызов accept-а завершился.
	struct current_accept_completed_t final : public so_5::signal_t {};

	//! Сигнал о том, что можно вернутся к приему новых подключений.
	struct enable_accepting_connections_t final : public so_5::signal_t {};

	//! Описание одного подключения от клиента.
	/*!
	 * В принципе, можно было бы в connection_map_t хранить просто
	 * connection_handler_shptr_t. Но наличие connection_info_t
	 * позволяет:
	 *
	 * - вызывать connection_handler_t::release() когда информация
	 *   о подключении удаляется вне зависимости от причины удаления;
	 * - позволяет в будущем расширить набор информации о соединении,
	 *   если надобность в этом возникнет.
	 */
	class connection_info_t
	{
		//! Текущий обработчик для этого подключения.
		connection_handler_shptr_t m_handler;

		// Конструктор копирования должен быть запрещен для этого типа.
		connection_info_t( const connection_info_t & ) = delete;
		connection_info_t &
		operator=( const connection_info_t & ) = delete;

		// Принудительный вызов release для обработчика,
		// который больше не нужен.
		static void
		release_handler( const connection_handler_shptr_t & handler_ptr )
		{
			if( handler_ptr )
				handler_ptr->release();
		}

	public:
		// Только конструктор и оператор перемещения доступны.
		connection_info_t( connection_info_t && ) = default;
		connection_info_t &
		operator=( connection_info_t && ) = default;

		connection_info_t(
			connection_handler_shptr_t handler )
			:	m_handler{ std::move(handler) }
		{}

		~connection_info_t()
		{
			// Перед уничтожением m_handler нужно обязательно
			// сделать вызов release(), чтобы завершить все текущие
			// IO-операции.
			release_handler( m_handler );
		}

		[[nodiscard]]
		const connection_handler_shptr_t &
		handler() const noexcept
		{
			return m_handler;
		}

		// Замена старого обработчика на новый.
		// Для старого обработчика автоматически вызывается release.
		connection_handler_shptr_t
		replace( connection_handler_shptr_t new_handler )
		{
			using std::swap;
			swap( m_handler, new_handler );

			release_handler( new_handler );

			return new_handler;
		}
	};

	//! Тип словаря подключений.
	using connection_map_t = std::map<
			handler_context_t::connection_id_t,
			connection_info_t >;

	//! Состояние верхнего уровня для агента.
	/*!
	 * В этом состоянии обрабатываются события, которые должны быть
	 * обработаны вне зависимости от текущего состояния агента.
	 * Например, обработка изменения конфигурации.
	 */
	state_t st_basic{ this, "basic" };

	//! Состояние, в котором точка входа еще не создана.
	state_t st_entry_not_created{
		initial_substate_of{ st_basic }, "entry_not_created" };

	//! Состояние, в котором точка входа создана и агент может
	//! принимать новые подключения.
	state_t st_entry_created{
		substate_of{ st_basic }, "entry_created" };

	//! Состояние, в котором точка входа создана и принимает
	//! новые подключения от клиентов.
	state_t st_accepting{
		initial_substate_of{ st_entry_created }, "accepting" };

	//! Состояние, в котором точка входа создана, но соединения
	//! не принимаются, т.к. достигнут разрешенный максимум.
	state_t st_too_many_connections{
		substate_of{ st_entry_created }, "too_many_connections" };

	//! Состояние, в котором агент дожидается возможности
	//! завершить свою работу.
	state_t st_shutting_down{ this, "shutting_down" };

	//! Контекст всего arataga.
	const application_context_t m_app_ctx;

	//! Индивидуальные параметры этого агента.
	const params_t m_params;

	//! Идивидуальная статистика этого ACL.
	::arataga::stats::connections::acl_stats_t m_acl_stats;
	::arataga::stats::connections::auto_reg_t m_acl_stats_reg;

	//! Текущие значения общих для всех ACL параметров.
	common_acl_params_t m_current_common_acl_params;

	//! Конфигурация для connection-handler-ов.
	actual_config_t m_connection_handlers_config;

	//! Серверный сокет, который будет принимать подключения.
	asio::ip::tcp::acceptor m_acceptor;

	//! Счетчик идентификаторов для новых подключений.
	handler_context_t::connection_id_t m_connection_id_counter{};

	//! Словарь текущих подключений.
	connection_map_t m_connections;

	//! Словарь успешно аутентифицированных клиентов.
	authentificated_user_map_t m_authentificated_users;

	void
	on_shutdown( mhood_t< shutdown_t > );

	void
	on_try_create_entry_point( mhood_t< try_create_entry_point_t > );

	void
	on_enter_st_entry_created() noexcept;

	void
	on_one_second_timer( mhood_t< one_second_timer_t > );

	void
	on_enter_st_accepting() noexcept;

	void
	on_accept_next_when_accepting( mhood_t< accept_next_t > );

	void
	on_accept_completion_when_accepting(
		mhood_t< current_accept_completed_t > );

	void
	on_dns_result(
		mhood_t< ::arataga::dns_resolver::resolve_reply_t > cmd );

	void
	on_auth_result(
		mhood_t< ::arataga::authentificator::auth_reply_t > cmd );

	void
	on_updated_config(
		mhood_t< ::arataga::config_processor::updated_common_acl_params_t > cmd );

	//! Получить доступ к описанию подключения по ID.
	/*!
	 * Описание этого подключения обязательно должно существовать.
	 * В противном случае порождается исключение.
	 */
	[[nodiscard]]
	connection_info_t &
	connection_info_that_must_be_present(
		connection_id_t id );

	//! Попробовать найти описание подключения по ID.
	/*!
	 * Описание подключения может отсутствовать. В этом случае
	 * возвращается нулевой указатель.
	 */
	[[nodiscard]]
	connection_info_t *
	try_find_connection_info(
		connection_id_t id );

	//! Прием нового подключения.
	void
	accept_new_connection(
		asio::ip::tcp::socket connection ) noexcept;

	//! Обновление информации о дефолтных лимитах при получении уведомления
	//! об изменении конфигурации.
	void
	update_default_bandlims_on_confg_change() noexcept;

	//! Пересчет квот по трафику при начале нового такта работы.
	void
	update_traffic_limit_quotes_on_new_turn();

	//! Реакция на успешную аутентификацию клиента.
	/*!
	 * Информация об этом клиенте должна попасть в m_authentificated_users.
	 *
	 * Возвращается traffic_limiter, который будет органичивать трафик
	 * для нового подключения.
	 */
	traffic_limiter_unique_ptr_t
	user_authentificated(
		const ::arataga::authentificator::successful_auth_t & info );

	//! Вспомогательный метод для формирования единообразного ID.
	/*!
	 * По этому ID в логе будет проще искать все связанные с
	 * конкретным соединением строки.
	 */
	::arataga::utils::acl_req_id_t
	make_long_id( connection_id_t id ) const noexcept;

	//! Вспомогательный метод для перехода в состояние приема новых
	//! подключений, если это позволяет конфигурация.
	void
	try_switch_to_accepting_if_necessary_and_possible();

	//! Обновление статистики по удаленным connection-handler-ам.
	void
	update_remove_handle_stats( remove_reason_t reason ) noexcept;
};

} /* namespace arataga::acl_handler */

