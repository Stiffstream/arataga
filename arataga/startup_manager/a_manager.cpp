/*!
 * @file
 * @brief Агент, который отвечает за организацию правильной последовательности
 * запуска основных агентов arataga.
 */

#include <arataga/startup_manager/a_manager.hpp>

#include <arataga/stats_collector/introduce_stats_collector.hpp>
#include <arataga/stats_collector/msg_get_stats.hpp>
#include <arataga/user_list_processor/pub.hpp>
#include <arataga/config_processor/pub.hpp>

#include <arataga/logging/wrap_logging.hpp>

#include <arataga/one_second_timer.hpp>

#include <arataga/exception.hpp>

#include <so_5_extra/mboxes/retained_msg.hpp>

namespace arataga::startup_manager
{

//
// startup_manager_ex_t
//
//! Тип исключения, которое может выбрасывать startup_manager.
struct startup_manager_ex_t : public exception_t
{
public:
	startup_manager_ex_t( const std::string & what )
		:	exception_t{ what }
	{}
};

namespace impl
{

//
// actual_requests_mailbox_t
//
//! Актуальная реализация интерфейса admin_http_entry::requests_mailbox.
class actual_requests_mailbox_t final
	:	public ::arataga::admin_http_entry::requests_mailbox_t
{
public:
	actual_requests_mailbox_t(
		application_context_t app_ctx )
		:	m_app_ctx{ std::move(app_ctx) }
	{}

	void
	new_config(
		::arataga::admin_http_entry::replier_shptr_t replier,
		std::string_view content ) override
	{
		so_5::send< ::arataga::config_processor::new_config_t >(
				m_app_ctx.m_config_processor_mbox,
				std::move(replier),
				std::move(content) );
	}

	void
	get_acl_list(
		::arataga::admin_http_entry::replier_shptr_t replier ) override
	{
		so_5::send< ::arataga::config_processor::get_acl_list_t >(
				m_app_ctx.m_config_processor_mbox,
				std::move(replier) );
	}

	void
	new_user_list(
		::arataga::admin_http_entry::replier_shptr_t replier,
		std::string_view content ) override
	{
		so_5::send< ::arataga::user_list_processor::new_user_list_t >(
				m_app_ctx.m_user_list_processor_mbox,
				std::move(replier),
				std::move(content) );
	}

	void
	get_current_stats(
		::arataga::admin_http_entry::replier_shptr_t replier ) override
	{
		so_5::send< ::arataga::stats_collector::get_current_stats_t >(
				m_app_ctx.m_stats_collector_mbox,
				std::move(replier) );
	}

	void
	debug_authentificate(
		::arataga::admin_http_entry::replier_shptr_t replier,
		::arataga::admin_http_entry::debug_requests::authentificate_t
				request ) override
	{
		so_5::send< ::arataga::config_processor::debug_auth_t >(
				m_app_ctx.m_config_processor_mbox,
				std::move(replier),
				std::move(request) );
	}

	void
	debug_dns_resolve(
		::arataga::admin_http_entry::replier_shptr_t replier,
		::arataga::admin_http_entry::debug_requests::dns_resolve_t
				request ) override
	{
		so_5::send< ::arataga::config_processor::debug_dns_resolve_t >(
				m_app_ctx.m_config_processor_mbox,
				std::move(replier),
				std::move(request) );
	}

private:
	const application_context_t m_app_ctx;
};

} /* namespace impl */

//
// a_manager_t
//
a_manager_t::a_manager_t(
	context_t ctx,
	params_t params )
	:	so_5::agent_t{ std::move(ctx) }
	,	m_params{ std::move(params) }
	,	m_app_ctx{ make_application_context( so_environment(), m_params ) }
	,	m_admin_entry_requests_mailbox{
			std::make_unique< impl::actual_requests_mailbox_t >( m_app_ctx ) }
{}

void
a_manager_t::so_define_agent()
{
	// ПРИМЕЧАНИЕ: методы обработки входа в состояния могут бросать
	// исключения. Но нас это не волнует, т.к. если здесь возникают
	// ошибки, то продолжать работу все равно нельзя.
	st_wait_user_list_processor
		.on_enter( [this]{ on_enter_wait_user_list_processor(); } )
		.event( &a_manager_t::on_user_list_processor_started )
		.event( &a_manager_t::on_user_list_processor_startup_timeout );

	st_wait_config_processor
		.on_enter( [this]{ on_enter_wait_config_processor(); } )
		.event( &a_manager_t::on_config_processor_started )
		.event( &a_manager_t::on_config_processor_startup_timeout );

	st_http_entry_stage
		.on_enter( [this]{ on_enter_http_entry_stage(); } )
		.event( &a_manager_t::on_make_admin_http_entry );
}

void
a_manager_t::so_evt_start()
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::info,
			[&]( auto & logger, auto level )
			{
				logger.log( level, "startup_manager: startup procedure started" );
			} );
	
	// Инициируем таймер, который будет срабатывать раз в секунду.
	m_one_second_timer = so_5::send_periodic< one_second_timer_t >(
			m_app_ctx.m_global_timer_mbox,
			std::chrono::seconds{1},
			std::chrono::seconds{1} );

	// Сразу же запускаем агента для сбора статистики, т.к. этот агент
	// не требует к себе какого-то пристального внимания.
	::arataga::stats_collector::introduce_stats_collector(
			so_environment(),
			so_coop(),
			// Агент будет работать на своем собственном контексте.
			so_5::disp::one_thread::make_dispatcher(
					so_environment(),
					"stats_collector" ).binder(),
			m_app_ctx,
			::arataga::stats_collector::params_t{} );

	// Ну а далее переходим к запуску более "тяжелых" агентов.

	this >>= st_wait_user_list_processor;
}

void
a_manager_t::so_evt_finish()
{
	// Если HTTP-вход запущен, то нужно дать ему команду на останов.
	if( m_admin_entry )
		m_admin_entry->stop();
}

application_context_t
a_manager_t::make_application_context(
	so_5::environment_t & env,
	const params_t & /*params*/ )
{
	application_context_t result;

	result.m_config_processor_mbox = env.create_mbox();
	result.m_user_list_processor_mbox = env.create_mbox();

	// В качестве этого mbox-а используется специальный retained_mbox,
	// который будет хранить последнее отправленное сообщение и
	// перепосылать его при новых подписках.
	// Это нужно, чтобы новые агенты могли получать сообщения об
	// изменениях в конфигурации, которые отсылались еще до запуска
	// этих новых агентов.
	result.m_config_updates_mbox = so_5::extra::mboxes::retained_msg::
			make_mbox( env );

	result.m_stats_collector_mbox = env.create_mbox();

	result.m_global_timer_mbox = env.create_mbox();

	result.m_acl_stats_manager = ::arataga::stats::connections::
			make_std_acl_stats_reference_manager();

	result.m_auth_stats_manager = ::arataga::stats::auth::
			make_std_auth_stats_reference_manager();

	result.m_dns_stats_manager = ::arataga::stats::dns::
			make_std_dns_stats_reference_manager();

	return result;
}

void
a_manager_t::on_enter_wait_user_list_processor()
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::debug,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"startup_manager: starting user_list_processor" );
			} );

	// Агент user_list_processor будет работать на своем собственном контексте.
	namespace ulp = arataga::user_list_processor;
	ulp::introduce_user_list_processor(
			so_environment(),
			so_5::disp::one_thread::make_dispatcher(
					so_environment(),
					"user_list_processor" ).binder(),
			m_app_ctx,
			ulp::params_t{
					m_params.m_local_config_path,
					so_direct_mbox()
			} );

	// Ограничиваем время ожидания user_list_processor.
	so_5::send_delayed< user_list_processor_startup_timeout >(
			*this,
			m_params.m_max_stage_startup_time );
}

void
a_manager_t::on_user_list_processor_started(
	mhood_t< arataga::user_list_processor::started_t > )
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::debug,
			[]( auto & logger, auto level )
			{
				logger.log(
						level,
						"startup_manager: user_list_processor started" );
			} );

	this >>= st_wait_config_processor;
}

[[noreturn]] void
a_manager_t::on_user_list_processor_startup_timeout(
	mhood_t< user_list_processor_startup_timeout > )
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::critical,
			[]( auto & logger, auto level )
			{
				logger.log(
						level,
						"startup_manager: user_list_processor startup timed-out" );
			} );

	// Выброс этого исключения приведет к завершению работы приложения.
	throw startup_manager_ex_t{ "user_list_processor startup timed-out" };
}

void
a_manager_t::on_enter_wait_config_processor()
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::debug,
			[]( auto & logger, auto level )
			{
				logger.log(
						level,
						"startup_manager: starting config_processor" );
			} );

	// Агент config_processor будет работать на своем собственном контексте.
	namespace cp = arataga::config_processor;
	cp::introduce_config_processor(
			so_environment(),
			so_5::disp::one_thread::make_dispatcher(
					so_environment(),
					"config_processor" ).binder(),
			m_app_ctx,
			cp::params_t{
					m_params.m_local_config_path,
					so_direct_mbox(),
					m_params.m_io_threads_count
			} );

	// Ограничиваем время ожидания config_processor.
	so_5::send_delayed< config_processor_startup_timeout >(
			*this,
			m_params.m_max_stage_startup_time );
}

void
a_manager_t::on_config_processor_started(
	mhood_t< arataga::config_processor::started_t > )
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::debug,
			[]( auto & logger, auto level )
			{
				logger.log(
						level,
						"startup_manager: config_processor started" );
			} );

	this >>= st_http_entry_stage;
}

[[noreturn]] void
a_manager_t::on_config_processor_startup_timeout(
	mhood_t< config_processor_startup_timeout > )
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::critical,
			[]( auto & logger, auto level )
			{
				logger.log(
						level,
						"startup_manager: config_processor startup timed-out" );
			} );

	// Выброс этого исключения приведет к завершению работы приложения.
	throw startup_manager_ex_t{ "config_processor startup timed-out" };
}

void
a_manager_t::on_enter_http_entry_stage()
{
	so_5::send< make_admin_http_entry >( *this );
}

void
a_manager_t::on_make_admin_http_entry(
	mhood_t< make_admin_http_entry > )
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::debug,
			[]( auto & logger, auto level )
			{
				logger.log(
						level,
						"startup_manager: starting HTTP-entry" );
			} );

	m_admin_entry = ::arataga::admin_http_entry::start_entry(
			m_params.m_admin_http_ip,
			m_params.m_admin_http_port,
			m_params.m_admin_http_token,
			*m_admin_entry_requests_mailbox );
}

//
// introduce_startup_manager
//
void
introduce_startup_manager(
	so_5::environment_t & env,
	params_t params )
{
	env.register_agent_as_coop(
			env.make_agent< a_manager_t >( std::move(params) ) );
}

} /* namespace arataga::startup_manager */

