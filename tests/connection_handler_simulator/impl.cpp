#include <tests/connection_handler_simulator/pub.hpp>

#include <arataga/acl_handler/connection_handler_ifaces.hpp>
#include <arataga/acl_handler/handler_factories.hpp>

#include <so_5_extra/disp/asio_one_thread/pub.hpp>

#include <so_5_extra/sync/pub.hpp>

#include <so_5/all.hpp>

#include <spdlog/sinks/null_sink.h>

#include <fmt/format.h>
#include <fmt/ostream.h>

using namespace std::chrono_literals;

namespace connection_handler_simulator
{

namespace aclh = arataga::acl_handler;

//
// actual_config_t
//
class actual_config_t : public aclh::config_t
{
	handler_config_values_t m_values;

public:
	actual_config_t( handler_config_values_t values )
		:	m_values{ std::move(values) }
	{}

	::arataga::acl_protocol_t
	acl_protocol() const noexcept override
	{
		return m_values.m_acl_protocol;
	}

	const asio::ip::address &
	out_addr() const noexcept override
	{
		return m_values.m_out_addr;
	}

	std::size_t
	io_chunk_size() const noexcept override
	{
		return m_values.m_io_chunk_size;
	}

	std::chrono::milliseconds
	protocol_detection_timeout() const noexcept override
	{
		return m_values.m_protocol_detection_timeout;
	}

	std::chrono::milliseconds
	socks_handshake_phase_timeout() const noexcept override
	{
		return m_values.m_socks_handshake_phase_timeout;
	}

	std::chrono::milliseconds
	dns_resolving_timeout() const noexcept override
	{
		return m_values.m_dns_resolving_timeout;
	}

	std::chrono::milliseconds
	authentification_timeout() const noexcept override
	{
		return m_values.m_authentification_timeout;
	}

	std::chrono::milliseconds
	connect_target_timeout() const noexcept override
	{
		return m_values.m_connect_target_timeout;
	}

	std::chrono::milliseconds
	socks_bind_timeout() const noexcept override
	{
		return m_values.m_socks_bind_timeout;
	}

	std::chrono::milliseconds
	idle_connection_timeout() const noexcept override
	{
		return m_values.m_idle_connection_timeout;
	}

	std::chrono::milliseconds
	http_headers_complete_timeout() const noexcept override
	{
		return m_values.m_http_headers_complete_timeout;
	}

	std::chrono::milliseconds
	http_negative_response_timeout() const noexcept override
	{
		return m_values.m_http_negative_response_timeout;
	}

	const ::arataga::http_message_value_limits_t &
	http_message_limits() const noexcept override
	{
		return m_values.m_http_message_limits;
	}
};

//
// noop_traffic_limiter_t
//
class noop_traffic_limiter_t final : public aclh::traffic_limiter_t
{
public:
	[[nodiscard]]
	reserved_capacity_t
	reserve_read_portion(
		direction_t /*dir*/,
		std::size_t buffer_size ) noexcept override
	{
		return { buffer_size, ::arataga::acl_handler::sequence_number_t{ 0u } };
	}

	void
	release_reserved_capacity(
		direction_t /*dir*/,
		reserved_capacity_t /*reserved_capacity*/,
		std::size_t /*actual_bytes*/ ) noexcept override
	{
	}
};

[[nodiscard]]
std::shared_ptr< spdlog::logger >
make_logger()
{
	auto existing_logger = spdlog::get( "imitator" );
	if( !existing_logger )
	{
		existing_logger = spdlog::null_logger_mt( "imitator" );
		existing_logger->set_level( spdlog::level::trace );
	}

	return existing_logger;
}

class a_handler_t final
	:	public so_5::agent_t
	,	public aclh::handler_context_t
{
public:
	a_handler_t(
		context_t ctx,
		asio::io_context & io_ctx,
		asio::ip::tcp::endpoint entry_point,
		handler_config_values_t config_values )
		:	so_5::agent_t{ std::move(ctx) }
		,	m_io_ctx{ io_ctx }
		,	m_entry_point{ entry_point }
		,	m_actual_config{ std::move(config_values) }
		,	m_logger_holder{ make_logger() }
	{}

	struct is_ready_ask_t {};
	struct is_ready_reply_t {};

	using is_ready_dialog_t = so_5::extra::sync::request_reply_t<
			is_ready_ask_t, is_ready_reply_t >;

	struct get_trace_request_t {};
	using get_trace_reply_t = std::vector< std::string >;

	using get_trace_dialog_t = so_5::extra::sync::request_reply_t<
			get_trace_request_t, get_trace_reply_t >;

	struct handle_dns_resolve_result_t final : public so_5::message_t
	{
		using handler_t = std::function< void() >;

		const handler_t m_handler;

		handle_dns_resolve_result_t( handler_t handler )
			:	m_handler{ std::move(handler) }
		{}
	};

	struct handle_authentification_result_t final : public so_5::message_t
	{
		using handler_t = std::function< void() >;

		const handler_t m_handler;

		handle_authentification_result_t( handler_t handler )
			:	m_handler{ std::move(handler) }
		{}
	};

	void
	so_define_agent() override
	{
		so_subscribe_self()
			.event( &a_handler_t::on_timer )
			.event( []( typename is_ready_dialog_t::request_mhood_t cmd ) {
					cmd->make_reply();
				} )
			.event( [this]( typename get_trace_dialog_t::request_mhood_t cmd ) {
					cmd->make_reply( m_trace );
				} )
			.event( []( const handle_dns_resolve_result_t & cmd ) {
					cmd.m_handler();
				} )
			.event( []( const handle_authentification_result_t & cmd ) {
					cmd.m_handler();
				} )
			;
	}

	void
	so_evt_start() override
	{
		// Нужно открыть серверный сокет.
		m_acceptor = std::make_unique< asio::ip::tcp::acceptor >(
				m_io_ctx,
				m_entry_point,
				true /* SO_REUSEADDR */ );
		m_acceptor->non_blocking( true );

		// Теперь можно запустить таймер для вызова on_timer у handler-ов.
		// Запускаем с более высоким темпом, т.к. в тестах времена
		// будут не такими большими, как в основном приложении.
		m_timer = so_5::send_periodic< timer_t >( *this, 100ms, 100ms );

		// Начинаем принимать новые подключения.
		accept_next();
	}

	void
	so_evt_finish() override
	{
		// Очищаем все, чем владеем.
		m_acceptor->close();
		m_connections.clear();
	}

	void
	replace_connection_handler(
		aclh::delete_protector_t,
		connection_id_t id,
		aclh::connection_handler_shptr_t handler ) override
	{
		auto & info = connection_info_that_must_be_present( id );

		auto old_handler = info.replace( std::move(handler) );

		log_message_for_connection( id,
				::arataga::logging::processed_log_level_t{spdlog::level::trace},
				fmt::format( "replace handler, old: {}, new: {}",
						old_handler->name(),
						info.handler()->name() ) );

		// Новый обработчик должен быть запущен.
		// ВНИМАНИЕ: в процессе выполнения этой операции обработчик
		// может быть заменен еще раз.
		info.handler()->on_start();
	}

	void
	remove_connection_handler(
		aclh::delete_protector_t,
		connection_id_t id,
		aclh::remove_reason_t /*reason*/ ) noexcept override
	{
		auto it = m_connections.find( id );
		if( it != m_connections.end() )
		{
			m_connections.erase( it );
		}
	}

	void
	log_message_for_connection(
		connection_id_t id,
		::arataga::logging::processed_log_level_t level,
		std::string_view message ) override
	{
		m_trace.push_back( fmt::format( "[{}] {}: {}",
				spdlog::level::to_string_view( level ),
				id,
				message )
			);
	}

	const aclh::config_t &
	config() const noexcept override
	{
		return m_actual_config;
	}

	void
	async_resolve_hostname(
		connection_id_t /*id*/,
		const std::string & hostname,
		aclh::dns_resolving::hostname_result_handler_t result_handler ) override
	{
		static const std::map< std::string, asio::ip::address > know_hosts{
			{ "ya.ru", asio::ip::make_address( "87.250.250.242" ) },
			{ "fb.com", asio::ip::make_address( "31.13.92.36" ) },
			{ "fb6.com", asio::ip::make_address( "2a03:2880:f11c:8083:face:b00c:0:25de" ) },
			{ "localhost", asio::ip::make_address( "127.0.0.1" ) }
		};

		const auto it = know_hosts.find( hostname );
		if( it != know_hosts.end() )
		{
			so_5::send< handle_dns_resolve_result_t >( *this,
				[result_handler, addr = it->second]() {
					result_handler(
							aclh::dns_resolving::hostname_found_t{ addr } );
				} );
		}
		else
		{
			so_5::send< handle_dns_resolve_result_t >( *this,
				[result_handler]() {
					result_handler(
							aclh::dns_resolving::hostname_not_found_t{
									"Unknown host"
								} );
				} );
		}
	}

	void
	async_authentificate(
		connection_id_t /*id*/,
		aclh::authentification::request_params_t request,
		aclh::authentification::result_handler_t result_handler ) override
	{
		static const std::set< std::pair< std::string, std::string > >
			know_users{
				{ "user", "12345" },
				{ "user1", "12345" }
			};

		const auto it = know_users.find( std::make_pair(
				request.m_username.value_or( "<-not-existent->" ),
				request.m_password.value_or( "<-not-existent->" ) ) );
		if( it != know_users.end() )
		{
			so_5::send< handle_authentification_result_t >( *this,
				[result_handler]() {
					result_handler( aclh::authentification::success_t{
							std::make_unique< noop_traffic_limiter_t >()
						} );
				} );
		}
		else
		{
			so_5::send< handle_authentification_result_t >( *this,
				[result_handler]() {
					result_handler(
							aclh::authentification::failure_t{
								aclh::authentification::failure_reason_t::unknown_user
							} );
				} );
		}
	}

	void
	stats_inc_connection_count(
		aclh::connection_type_t /*connection_type*/ ) override
	{
		// Ничего делать не нужно.
	}

private:
	struct timer_t final : public so_5::signal_t {};

	class connection_info_t
	{
		aclh::connection_handler_shptr_t m_handler;

		// Конструктор копирования должен быть запрещен для этого типа.
		connection_info_t( const connection_info_t & ) = delete;
		connection_info_t &
		operator=( const connection_info_t & ) = delete;

		// Принудительный вызов release для обработчика,
		// который больше не нужен.
		static void
		release_handler( const aclh::connection_handler_shptr_t & handler_ptr )
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
			aclh::connection_handler_shptr_t handler )
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
		const aclh::connection_handler_shptr_t &
		handler() const noexcept
		{
			return m_handler;
		}

		// Замена старого обработчика на новый.
		// Для старого обработчика автоматически вызывается release.
		aclh::connection_handler_shptr_t
		replace( aclh::connection_handler_shptr_t new_handler )
		{
			using std::swap;
			swap( m_handler, new_handler );

			release_handler( new_handler );

			return new_handler;
		}
	};

	using connection_map_t = std::map< connection_id_t, connection_info_t >;

	asio::io_context & m_io_ctx;

	asio::ip::tcp::endpoint m_entry_point;

	actual_config_t m_actual_config;

	::arataga::logging::logger_holder_t m_logger_holder;

	std::unique_ptr< asio::ip::tcp::acceptor > m_acceptor;

	so_5::timer_id_t m_timer;

	connection_id_t m_connection_id_counter{};

	connection_map_t m_connections;

	std::vector< std::string > m_trace;

	void
	on_timer( mhood_t< timer_t > )
	{
		for( auto it = m_connections.begin(); it != m_connections.end(); )
		{
			// Держим указатель у себя до тех пор, пока не завершится on_timer.
			auto handler = it->second.handler();
			++it; // Обязательно идем к следующему элементу пока it валиден.

			handler->on_timer();
		}
	}

	[[nodiscard]]
	connection_info_t &
	connection_info_that_must_be_present(
		connection_id_t id )
	{
		auto it = m_connections.find( id );
		if( it == m_connections.end() )
			throw std::runtime_error{
					fmt::format( "unknown connection id: {}", id )
				};

		return it->second;
	}

	void
	accept_next()
	{
		m_acceptor->async_accept(
				[self = so_5::make_agent_ref(this)](
					const asio::error_code & ec,
					asio::ip::tcp::socket connection )
				{
					if( !ec )
					{
						self->accept_new_connection( std::move(connection) );
						self->accept_next();
					}
				} );
	}

	void
	accept_new_connection(
		asio::ip::tcp::socket connection )
	{
		// Для нового подключения нужен новый ID.
		const auto id = ++m_connection_id_counter;

		// Для нового подключения нужен начальный обработчик.
		auto handler = aclh::make_protocol_detection_handler(
				aclh::handler_context_holder_t{ so_5::make_agent_ref(this), *this },
				id,
				std::move(connection) );

		// Запускаем начальный обработчик.
		handler->on_start();

		// Новое соединение должно быть сохранено в списке известных
		// нам подключений.
		m_connections.emplace( id,
				connection_info_t{ std::move(handler) } );
	}
};

struct simulator_t::internals_t
{
	so_5::wrapped_env_t m_sobjectizer;
	so_5::mbox_t m_simulator_mbox;

	internals_t()
		:	m_sobjectizer{
				[]( so_5::environment_t & ) { /* ничего не делаем */ }
			}
	{}
};

simulator_t::simulator_t(
	asio::ip::tcp::endpoint entry_point,
	handler_config_values_t config_values )
	:	m_impl{ new internals_t{} }
{
	namespace asio_disp = so_5::extra::disp::asio_one_thread;
	auto disp = asio_disp::make_dispatcher(
			m_impl->m_sobjectizer.environment(),
			"asio_disp",
			asio_disp::disp_params_t{}.use_own_io_context() );

	m_impl->m_simulator_mbox =
			m_impl->m_sobjectizer.environment().introduce_coop(
					disp.binder(),
					[&]( so_5::coop_t & coop ) {
						auto simulator = coop.make_agent< a_handler_t >(
								disp.io_context(),
								entry_point,
								std::move(config_values) );
						return simulator->so_direct_mbox();
					} );

	// Нужно подождать, пока симулятор будет готов.
	(void)a_handler_t::is_ready_dialog_t::ask_value( m_impl->m_simulator_mbox, 2s );
}

simulator_t::~simulator_t()
{
	m_impl->m_sobjectizer.stop_then_join();
}

std::vector< std::string >
simulator_t::get_trace()
{
	return a_handler_t::get_trace_dialog_t::ask_value(
			m_impl->m_simulator_mbox, 2s );
}

} /* namespace connection_handler_simulator */

