/*!
 * @file
 * @brief Агент для обработки списка пользователей.
 */

#include <arataga/user_list_processor/a_processor.hpp>
#include <arataga/user_list_processor/notifications.hpp>

#include <arataga/user_list_auth_data.hpp>

#include <arataga/admin_http_entry/helpers.hpp>

#include <arataga/utils/load_file_into_memory.hpp>

#include <arataga/logging/wrap_logging.hpp>

#include <arataga/exception.hpp>

namespace arataga::user_list_processor
{

//
// user_list_processor_ex_t
//
//! Тип исключения, которое может выбрасывать user_list_processor.
struct user_list_processor_ex_t : public exception_t
{
public:
	user_list_processor_ex_t( const std::string & what )
		:	exception_t{ what }
	{}
};

//
// a_processor_t
//
a_processor_t::a_processor_t(
	context_t ctx,
	application_context_t app_ctx,
	params_t params )
	:	so_5::agent_t{ std::move(ctx) }
	,	m_app_ctx{ std::move(app_ctx) }
	,	m_params{ std::move(params) }
	,	m_local_user_list_file_name{
			m_params.m_local_config_path / "local-user-list.cfg" }
{}

void
a_processor_t::so_define_agent()
{
	so_subscribe( m_app_ctx.m_user_list_processor_mbox )
		.event( &a_processor_t::on_new_user_list );
}

void
a_processor_t::so_evt_start()
{
	try_load_local_user_list_first_time();

	// Можно подтвердить, что агент стартовал.
	so_5::send< started_t >( m_params.m_startup_notify_mbox );
}

void
a_processor_t::on_new_user_list(
	mhood_t< new_user_list_t > cmd )
{
	namespace http_entry = ::arataga::admin_http_entry;

	http_entry::envelope_sync_request_handling(
			"user_list_processor::a_processor_t::on_new_user_list",
			*(cmd->m_replier),
			http_entry::status_user_list_processor_failure,
			[&]() -> http_entry::replier_t::reply_params_t
			{
				try_handle_new_user_list_from_post_request( cmd->m_content );

				// Если оказались здесь, значит все прошло нормально.
				return http_entry::replier_t::reply_params_t{
						http_entry::status_ok,
						"New user list accepted\r\n"
				};
			} );
}

void
a_processor_t::try_load_local_user_list_first_time()
{
	auto auth_data = try_load_local_user_list_content();

	if( auth_data )
	{
		// Поскольку список пользователей успешно загружен, то можно
		// отослать его всем желающим.
		distribute_updated_user_list( std::move(*auth_data) );
	}
}

void
a_processor_t::try_handle_new_user_list_from_post_request(
	std::string_view content )
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::info,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"user_list_processor: {} byte(s) received "
							"from admin HTTP-entry",
						content.size() );
			} );

	// Пытаемся разобрать конфиг.
	auto auth_data = ::arataga::user_list_auth::parse_auth_data( content );

	// И если уж успешно разобрали, то сохраняем его в виде локального файла...
	store_new_user_list_to_file( content );

	// ...и рассылаем уведомление о новом списке пользоваталей.
	distribute_updated_user_list( std::move(auth_data) );

	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::info,
			[]( auto & logger, auto level )
			{
				logger.log(
						level,
						"user_list_processor: new user-list processed" );
			} );
}

std::optional< ::arataga::user_list_auth::auth_data_t >
a_processor_t::try_load_local_user_list_content()
{
	std::optional< ::arataga::user_list_auth::auth_data_t > result;

	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::info,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"user_list_processor: trying load local "
						"user-list file at startup, "
						"local_user_list_file_name: {}",
						m_local_user_list_file_name.string() );
			} );

	// Исключения, которые возникают при попытке загрузить локальный файл со
	// списком пользователей можно игнорировать, т.к. даже в случае неудачи нам
	// должны будут прислать новый список через HTTP-вход.
	try
	{
		// Используем здесь лямбду для того, чтобы content
		// был автоматически удален сразу после парсинга, т.к.
		// больше содержимое конфига нам не нужно.
		result = [this] {
			// Содержимое файла нужно поднять в память...
			auto content = ::arataga::utils::load_file_into_memory(
					m_local_user_list_file_name );
			::arataga::logging::wrap_logging(
					direct_logging_mode,
					spdlog::level::trace,
					[&content]( auto & logger, auto level )
					{
						logger.log(
								level,
								"user_list_processor: {} byte(s) loaded "
								"from local user-list file",
								content.size() );
					} );

			// ...и попробовать разобрать его.
			return ::arataga::user_list_auth::parse_auth_data(
					std::string_view{ content.data(), content.size() } );
		}();
	}
	catch( const std::exception & x )
	{
		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::err,
				[&x]( auto & logger, auto level )
				{
					logger.log(
							level,
							"user_list_processor: load local "
							"user-list file at startup failed: {}",
							x.what() );
				} );
	}

	return result;
}

void
a_processor_t::distribute_updated_user_list(
	::arataga::user_list_auth::auth_data_t auth_data ) noexcept
{
	bool needs_terminate = false;

	try
	{
		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::debug,
				[&]( auto & logger, auto level )
				{
					logger.log(
							level,
							"user_list_processor: distribution of new user-list" );
				} );

		so_5::send< updated_user_list_t >(
				m_app_ctx.m_config_updates_mbox,
				std::move(auth_data) );
	}
	catch( const std::exception & x )
	{
		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::critical,
				[&x]( auto & logger, auto level )
				{
					logger.log(
							level,
							"user_list_processor: "
							"an exception caught during distribution of new user-list: {}",
							x.what() );
				} );

		needs_terminate = true;
	}
	catch( ... )
	{
		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::critical,
				[]( auto & logger, auto level )
				{
					logger.log(
							level,
							"user_list_processor: "
							"unknown exception caught during "
							"distribution of new user-list" );
				} );

		needs_terminate = true;
	}

	if( needs_terminate )
	{
		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::critical,
				[]( auto & logger, auto level )
				{
					logger.log(
							level,
							"user_list_processor: "
							"work can't be continued, aborting..." );
				} );

		std::abort();
	}
}

void
a_processor_t::store_new_user_list_to_file(
	std::string_view content )
{
	try
	{
		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::trace,
				[&]( auto & logger, auto level )
				{
					logger.log(
							level,
							"user_list_processor: updating local "
							"user-list file {}",
							m_local_user_list_file_name );
				} );

		std::ofstream file( m_local_user_list_file_name,
				std::ios_base::out | std::ios_base::binary |
						std::ios_base::trunc );
		if( !file )
			::arataga::utils::ensure_successful_syscall( -1,
					fmt::format( "unable to open local user-list file {} for "
							"writting", m_local_user_list_file_name ) );

		file.exceptions( std::ifstream::badbit | std::ifstream::failbit );

		file.write(
				content.data(),
				static_cast<std::streamsize>(content.size()) );

		file.close();
	}
	catch( const std::exception & x )
	{
		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::err,
				[&]( auto & logger, auto level )
				{
					logger.log(
							level,
							"user_list_processor: error storing new "
							"user-list into local file {}: {}",
							m_local_user_list_file_name,
							x.what() );
				} );
	}
}

//
// introduce_user_list_processor
//
void
introduce_user_list_processor(
	so_5::environment_t & env,
	so_5::disp_binder_shptr_t disp_binder,
	application_context_t app_ctx,
	params_t params )
{
	env.introduce_coop(
			disp_binder,
			[&]( so_5::coop_t & coop ) {
				coop.make_agent< a_processor_t >(
						std::move(app_ctx),
						std::move(params) );
			} );
}

} /* namespace arataga::user_list_processor */

