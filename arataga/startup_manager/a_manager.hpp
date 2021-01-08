/*!
 * @file
 * @brief Агент, который отвечает за организацию правильной последовательности
 * запуска основных агентов arataga.
 */

#pragma once

#include <arataga/startup_manager/pub.hpp>

#include <arataga/user_list_processor/notifications.hpp>
#include <arataga/config_processor/notifications.hpp>

#include <arataga/admin_http_entry/pub.hpp>

#include <so_5/all.hpp>

#include <filesystem>

namespace arataga::startup_manager
{

//
// a_manager_t
//
/*!
 * @brief Агент для запуска основных агентов arataga в правильной
 * последовательности.
 *
 * Именно этот агент создает экземпляр application_context, который затем
 * используется для инициализации всех остальных агентов в приложении.
 *
 * Порядок запуска агентов:
 * - user_list_processor;
 * - config_processor.
 *
 */
class a_manager_t : public so_5::agent_t
{
public:
	//! Основной конструктор.
	a_manager_t(
		//! SOEnv и SObjectizer-овские параметры для агента.
		context_t ctx,
		//! Индивидуальные параметры для этого агента.
		params_t params );

	void
	so_define_agent() override;

	void
	so_evt_start() override;

	void
	so_evt_finish() override;

private:
	//! Уведомление о том, что user_list_processor вовремя не стартовал.
	struct user_list_processor_startup_timeout final : public so_5::signal_t {};

	//! Уведомление о том, что config_processor вовремя не стартовал.
	struct config_processor_startup_timeout final : public so_5::signal_t {};

	//! Команда на создание административного HTTP-входа в приложение.
	struct make_admin_http_entry final : public so_5::signal_t {};

	//! Индивидуальные параметры для этого агента.
	const params_t m_params;

	//! Контекст всего приложения, который должен использоваться
	//! остальными агентами.
	const application_context_t m_app_ctx;

	//! Состояние, в котором ждем завершения запуска user_list_processor.
	state_t st_wait_user_list_processor{ this, "wait_user_list_processor" };
	//! Состояние, в котором ждем завершения запуска config_processor.
	state_t st_wait_config_processor{ this, "wait_config_processor" };
	//! Состояние, в котором запускаем административный HTTP-вход.
	state_t st_http_entry_stage{ this, "http_entry_stage" };
	//! Нормальное состояние при котором все компоненты запущены.
	state_t st_normal{ this, "normal" };

	//! Таймер, который будет срабатывать раз в секунду.
	so_5::timer_id_t m_one_second_timer;

	//! Реализация интерфейса для коммуникации HTTP-входа с
	//! SObjectizer-овской частью.
	std::unique_ptr< ::arataga::admin_http_entry::requests_mailbox_t >
			m_admin_entry_requests_mailbox;

	//! Административный HTTP-вход.
	::arataga::admin_http_entry::running_entry_handle_t m_admin_entry;

	//! Создать экземпляр контекста всего приложения.
	[[nodiscard]]
	static application_context_t
	make_application_context(
		so_5::environment_t & env,
		const params_t & params );

	//! Реакция на вход в состояние wait_user_list_processor.
	/*!
	 * Выполняется создание агента user_list_processor.
	 */
	void
	on_enter_wait_user_list_processor();

	//! Реакция на начало работы user_list_processor.
	void
	on_user_list_processor_started(
		mhood_t< arataga::user_list_processor::started_t > );

	//! Реакция на истечение времени старта для user_list_processor.
	[[noreturn]] void
	on_user_list_processor_startup_timeout(
		mhood_t< user_list_processor_startup_timeout > );

	//! Реакция на вход в состояние wait_config_processor.
	/*!
	 * Выполняется создание агента config_processor.
	 */
	void
	on_enter_wait_config_processor();

	//! Реакция на начало работы config_processor.
	void
	on_config_processor_started(
		mhood_t< arataga::config_processor::started_t > );

	//! Реакция на истечение времени старта для config_processor.
	[[noreturn]] void
	on_config_processor_startup_timeout(
		mhood_t< config_processor_startup_timeout > );

	//! Реакция на вход в состояние http_entry_stage.
	/*!
	 * Агент сам себе отсылает команду make_admin_http_entry.
	 *
	 * Нельзя выполнять действия, которые могут бросить исключения
	 * в обработчике входа в состояние. Поэтому создание точки
	 * входа делегируется в обычный обработчик сообщения.
	 */
	void
	on_enter_http_entry_stage();

	//! Реакция на команду создания административного HTTP-входа.
	void
	on_make_admin_http_entry(
		mhood_t< make_admin_http_entry > );
};

} /* namespace arataga::startup_manager */

