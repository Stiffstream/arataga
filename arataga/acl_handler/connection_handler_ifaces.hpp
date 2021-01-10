/*!
 * @file
 * @brief Интерфейсы, необходимые для обработчиков подключений.
 */

#pragma once

#include <arataga/acl_handler/sequence_number.hpp>

#include <arataga/utils/can_throw.hpp>

#include <arataga/config.hpp>

#include <arataga/logging/wrap_logging.hpp>

#include <so_5/all.hpp>

#include <asio/ip/tcp.hpp>
#include <asio/write.hpp>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <spdlog/spdlog.h>

#include <noexcept_ctcheck/pub.hpp>

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <string_view>

namespace arataga::acl_handler
{

//
// config_t
//
/*!
 * @brief Интерфейс объекта, предоставляющего доступ к конфигурационной
 * информации.
 */
class config_t
{
public:
	virtual ~config_t();

	[[nodiscard]]
	virtual acl_protocol_t
	acl_protocol() const noexcept = 0;

	[[nodiscard]]
	virtual const asio::ip::address &
	out_addr() const noexcept = 0;

	[[nodiscard]]
	virtual std::size_t
	io_chunk_size() const noexcept = 0;

	[[nodiscard]]
	virtual std::size_t
	io_chunk_count() const noexcept = 0;

	[[nodiscard]]
	virtual std::chrono::milliseconds
	protocol_detection_timeout() const noexcept = 0;

	[[nodiscard]]
	virtual std::chrono::milliseconds
	socks_handshake_phase_timeout() const noexcept = 0;

	[[nodiscard]]
	virtual std::chrono::milliseconds
	dns_resolving_timeout() const noexcept = 0;

	[[nodiscard]]
	virtual std::chrono::milliseconds
	authentification_timeout() const noexcept = 0;

	[[nodiscard]]
	virtual std::chrono::milliseconds
	connect_target_timeout() const noexcept = 0;

	[[nodiscard]]
	virtual std::chrono::milliseconds
	socks_bind_timeout() const noexcept = 0;

	[[nodiscard]]
	virtual std::chrono::milliseconds
	idle_connection_timeout() const noexcept = 0;

	[[nodiscard]]
	virtual std::chrono::milliseconds
	http_headers_complete_timeout() const noexcept = 0;

	[[nodiscard]]
	virtual std::chrono::milliseconds
	http_negative_response_timeout() const noexcept = 0;

	[[nodiscard]]
	virtual const http_message_value_limits_t &
	http_message_limits() const noexcept = 0;
};

//
// remove_reason_t
//
//! Почему следует удалять connection-handler.
enum remove_reason_t
{
	//! Нормальное завершение работы с соединением.
	normal_completion,
	//! Ошибка ввода-вывода.
	io_error,
	//! Истекло время на выполнение текущей операции.
	current_operation_timed_out,
	//! Данный проткол не поддерживается.
	unsupported_protocol,
	//! Ошибка протокола. Например, неподдерживаемая версия протокола.
	protocol_error,
	//! Возникновение ситуации, которая не предполагалась и которая
	//! не может быть обработана как-то иначе.
	unexpected_and_unsupported_case,
	//! Слишком долго нет активности в соединении.
	no_activity_for_too_long,
	//! Текущая операция была прервана извне.
	current_operation_canceled,
	//! Поймано необработанное в connection-handler-е исключение.
	unhandled_exception,
	//! Несовпадение версий IP-адресов.
	//! Например, невозможно подключиться к IPv6 адресу с IPv4 адреса.
	ip_version_mismatch,
	//! Пользователю запрещен доступ.
	access_denied,
	//! Не удалось установить адрес хоста, к которому нужно подключаться.
	unresolved_target,
	//! Подключение к целевому узлу оказалось закрытым.
	target_end_broken,
	//! Подключение со стороны клиента оказалось закрытым.
	user_end_broken,
	//! HTTP-ответ был получен еще до завершения HTTP-запроса.
	http_response_before_completion_of_http_request,
	//! Клиент закрыл соединение на своей стороне.
	user_end_closed_by_client,
	//! Клиент не прислал новый входящий HTTP-запрос.
	http_no_incoming_request
};

[[nodiscard]]
inline std::string_view
to_string_view( remove_reason_t reason )
{
	std::string_view result{ "<unknown>" };
	switch( reason )
	{
	case remove_reason_t::normal_completion:
		result = "normal_completion";
	break;

	case remove_reason_t::io_error:
		result = "io_error";
	break;

	case remove_reason_t::current_operation_timed_out:
		result = "current_operation_timed_out";
	break;

	case remove_reason_t::unsupported_protocol:
		result = "unsupported_protocol";
	break;

	case remove_reason_t::protocol_error:
		result = "protocol_error";
	break;

	case remove_reason_t::unexpected_and_unsupported_case:
		result = "unexpected_and_unsupported_case";
	break;

	case remove_reason_t::no_activity_for_too_long:
		result = "no_activity_for_too_long";
	break;

	case remove_reason_t::current_operation_canceled:
		result = "current_operation_canceled";
	break;

	case remove_reason_t::unhandled_exception:
		result = "unhandled_exception";
	break;

	case remove_reason_t::ip_version_mismatch:
		result = "ip_version_mismatch";
	break;

	case remove_reason_t::access_denied:
		result = "access_denied";
	break;

	case remove_reason_t::unresolved_target:
		result = "unresolved_target";
	break;

	case remove_reason_t::target_end_broken:
		result = "target_end_broken";
	break;

	case remove_reason_t::user_end_broken:
		result = "user_end_broken";
	break;

	case remove_reason_t::http_response_before_completion_of_http_request:
		result = "http_response_before_completion_of_http_request";
	break;

	case remove_reason_t::user_end_closed_by_client:
		result = "user_end_closed_by_client";
	break;

	case remove_reason_t::http_no_incoming_request:
		result = "http_no_incoming_request";
	break;
	}

	return result;
}

inline std::ostream &
operator<<( std::ostream & to, remove_reason_t reason )
{
	return (to << to_string_view(reason));
}

// Сам класс будет определен позже.
class connection_handler_t;

//
// connection_handler_shptr_t
//
/*!
 * @brief Тип умного указателя на connection_handler.
 */
using connection_handler_shptr_t = std::shared_ptr< connection_handler_t >;

//
// traffic_limiter_t
//
/*!
 * @brief Интерфейс объекта, который отвечает за ограничение трафика
 * по подключению.
 *
 * Реализация этого интерфейса в своем деструкторе должна подчищать
 * за собой все ресурсы.
 */
class traffic_limiter_t
{
public:
	enum class direction_t { from_user, from_target };

	/*!
	 * @brief Описание результата запроса объема данных для чтения
	 * на текущем такте.
	 *
	 * Если из направления можно читать, то m_capacity будет содержать
	 * разрешенный объем для однократного чтения.
	 * После завершения чтения у объекта reserved_capacity_t нужно
	 * вызвать метод release().
	 */
	struct reserved_capacity_t
	{
		std::size_t m_capacity;
		sequence_number_t m_sequence_number;

		//! Метод для регистрации результата операции ввода-вывода
		//! в traffic-limiter-е.
		/*!
		 * Этот метод сам анализирует значение кода ошибки и, если
		 * ошибка произошла, считает, что прочитано 0 байт.
		 *
		 * @attention
		 * Этот метод обязательно должен вызываться при получении
		 * результата ввода-вывода. Поскольку в противном случае
		 * емкость, которая была зарезервирована для текущей операции
		 * так и останется занятой до конца такта.
		 */
		void
		release(
			traffic_limiter_t & limiter,
			direction_t dir,
			const asio::error_code & ec,
			std::size_t bytes_transferred ) const noexcept;
	};

	traffic_limiter_t( const traffic_limiter_t & ) = delete;
	traffic_limiter_t( traffic_limiter_t && ) = delete;

	traffic_limiter_t();
	virtual ~traffic_limiter_t();

	// Может возвращать значение 0.
	// В этом случае нужно прекратить попытки чтения данных до
	// наступления следующего такта работы.
	[[nodiscard]]
	virtual reserved_capacity_t
	reserve_read_portion(
		direction_t dir,
		std::size_t buffer_size ) noexcept = 0;

	virtual void
	release_reserved_capacity(
		direction_t dir,
		reserved_capacity_t reserved_capacity,
		std::size_t actual_bytes ) noexcept = 0;
};

//
// traffic_limiter_unique_ptr_t
//
/*!
 * @brief Псевдоним unique_ptr для traffic_limiter-а.
 */
using traffic_limiter_unique_ptr_t =
	std::unique_ptr< traffic_limiter_t >;

namespace dns_resolving
{

//! Результат успешного резолвинга доменного имени.
struct hostname_found_t
{
	//! Адрес, который соответствует доменному имени.
	asio::ip::address m_ip;
};

//! Результат неудачного резолвинга доменного имени.
struct hostname_not_found_t
{
	//! Описание причины неудачи.
	std::string m_error_desc;
};

//! Тип результата резолвинга доменного имени.
using hostname_result_t = std::variant<
		hostname_found_t,
		hostname_not_found_t
	>;

//! Тип функтора, который должен быть вызван при завершении
//! резолвинга доменного имени.
using hostname_result_handler_t =
	std::function< void(const hostname_result_t &) >;

} /* namespace dns_resolving */

namespace authentification
{

//! Параметры запроса на аутентификацию.
struct request_params_t
{
	asio::ip::address_v4 m_user_ip;
	std::optional< std::string > m_username;
	std::optional< std::string > m_password;
	std::string m_target_host;
	std::uint16_t m_target_port;
};

//! Причина неудачной аутентификации пользователя.
enum class failure_reason_t
{
	unknown_user,
	target_blocked
};

[[nodiscard]]
inline std::string_view
to_string_view( failure_reason_t reason )
{
	switch( reason )
	{
	case failure_reason_t::unknown_user: return "user unknown";
	case failure_reason_t::target_blocked: return "target is blocked for user";
	}

	return "<unknown>";
}

//! Отрицательный результате аутентификации.
struct failure_t
{
	failure_reason_t m_reason;
};

//! Положительный результат аутентификации.
struct success_t
{
	//! Объект, который будет ограничивать трафик для подключения.
	traffic_limiter_unique_ptr_t m_traffic_limiter;
};

//! Тип результата аутентификации пользователя.
using result_t = std::variant< failure_t, success_t >;

//! Тип функтора, который должен быть вызван при завершении
//! аутентификации пользователя.
using result_handler_t =
	// Значение в функцию передается по значению для
	// того, чтобы из result_t можно было забирать move-only значения.
	std::function< void(result_t) >;

} /* namespace dns_resolving */

//
// connection_type_t
//
/*!
 * @brief Различные варианты типов подключения.
 */
enum class connection_type_t
{
	//! Тип подключения еще неизвестен.
	//! Этот элемент перечисления должен использоваться для подсчета
	//! общего количества подключений.
	generic,
	//! Подключение по протоколу SOCKS5.
	socks5,
	//! Подключение по протоколу HTTP.
	http
};

namespace details {

class delete_protector_maker_t;

} /* namespace details */

//
// delete_protector_t
//
/*!
 * @brief Специальный маркер, наличие которого показывает, что
 * connection_handler защищен от удаления и можно безопасно заменять
 * текущий connection_handler новым connection_handler-ом.
 *
 * Сам по себе экземпляр класса delete_protector не делает ничего.
 * Но его наличие показывает, что где-то выше по стеку находится
 * экземпляр details::delete_protector_maker_t, который как раз
 * и препятствует преждевременному уничтожению connection_handler-а.
 *
 * Надобность в подобном классе возникла из-за того, что connection_handler
 * вызывает методы remove_connection_handler и replace_connection_handler
 * у handler_context_t внутри своих методов. В результате работы
 * remove_connection_handler/replace_connection_handler может получиться
 * так, что текущий connection_handler будет удален. Т.е. значение
 * this внутри текущего метода может стать невалидным. А это может
 * привести к возникновению ошибок из категории use after free (например,
 * если к this произойдет обращение уже после возврата из
 * remove_connection_handler/replace_connection_handler).
 *
 * Чтобы избежать ошибок use after free используется схема, в которой
 * сперва создается дополнительный экземпляр connection_handler_shptr_t,
 * а уже затем запукается тот или иной метод connection_handler-а.
 * Этот дополнительный (охранный) экземпляр connection_handler_shptr_t не
 * позволяет уничтожать connection_handler-а даже если после
 * remove_connection_handler/replace_connection_handler на этот 
 * connection_handler больше никто не ссылается. Тем самым значение
 * this остается валидным и к this можно обращаться даже после
 * возврата из remove_connection_handler/replace_connection_handler.
 */
class delete_protector_t
{
	friend class delete_protector_maker_t;

	delete_protector_t() noexcept = default;

public:
	~delete_protector_t() noexcept = default;

	delete_protector_t( const delete_protector_t & ) noexcept = default;
	delete_protector_t( delete_protector_t && ) noexcept = default;

	delete_protector_t &
	operator=( const delete_protector_t & ) noexcept = default;
	delete_protector_t &
	operator=( delete_protector_t && ) noexcept = default;
};

namespace details {

class delete_protector_maker_t
{
public:
	delete_protector_maker_t( connection_handler_shptr_t & ) {}

	[[nodiscard]]
	delete_protector_t
	make() const noexcept { return {}; }
};

} /* namespace details */

//
// handler_context_t
//
/*!
 * @brief Интерфейс объекта, представляющего собой контекст, внутри
 * которого обрабатываются подключения от клиентов.
 */
class handler_context_t
{
public:
	virtual ~handler_context_t();

	//! Идентификатор подключения в рамках этого контекста.
	using connection_id_t = std::uint_fast64_t;

	virtual void
	replace_connection_handler(
		delete_protector_t,
		connection_id_t id,
		connection_handler_shptr_t handler ) = 0;

	virtual void
	remove_connection_handler(
		delete_protector_t,
		connection_id_t id,
		remove_reason_t reason ) noexcept = 0;

	// ПРИМЕЧАНИЕ: этот метод должен вызываться внутри
	// logging::wrap_logging!
	virtual void
	log_message_for_connection(
		connection_id_t id,
		::arataga::logging::processed_log_level_t level,
		std::string_view message ) = 0;

	[[nodiscard]]
	virtual const config_t &
	config() const noexcept = 0;

	virtual void
	async_resolve_hostname(
		connection_id_t id,
		const std::string & hostname,
		dns_resolving::hostname_result_handler_t result_handler ) = 0;

	virtual void
	async_authentificate(
		connection_id_t id,
		authentification::request_params_t request,
		authentification::result_handler_t result_handler ) = 0;

	virtual void
	stats_inc_connection_count(
		connection_type_t connection_type ) = 0;
};

//
// handler_context_holder_t
//
/*!
 * @brief Специальный класс, который гарантирует, что handler_context
 * будет существовать, пока на него держат умную ссылку.
 *
 * Опасность асинхронных операций на io_context из Asio в том, что
 * обработчик результата IO-операции может быть вызван Asio уже после того,
 * как реализация handler_context-а завершила свою работу. И если
 * connection-handler захочет дернуть какую-то операцию из handler_context-а
 * (например, log_message_for_connection), то может выянится, что
 * connection-handler владеет "протухшей" ссылкой на handler_context.
 *
 * Чтобы этого не происходило, класс handler_context_holder_t играет
 * роль умной ссылки (или умного указателя) на handler_context. Что
 * гарантирует, что если connection-handler держит у себя экземпляр
 * handler_context_holder_t, то ссылка на handler_context останется
 * валидной, даже если handler_context уже завершил основную свою
 * работу и остается жить до тех пор, пока не исчезнут все
 * connection-handler-ы.
 */
class handler_context_holder_t
{
	//! Умный указатель на объект, который хранит в себе handler_context.
	so_5::agent_ref_t m_holder_agent;

	//! Ссылка на актуальный handler_context.
	std::reference_wrapper< handler_context_t > m_context;

public:
	handler_context_holder_t(
		so_5::agent_ref_t holder_agent,
		handler_context_t & context ) noexcept
		:	m_holder_agent{ std::move(holder_agent) }
		,	m_context{ context }
	{}

	[[nodiscard]]
	handler_context_t &
	ctx() const noexcept { return m_context.get(); }
};

//
// connection_handler_t
//
/*!
 * @brief Интерфейс обработчика для соединения.
 *
 * Это не просто интерфейс, но и базовый класс для обработчиков,
 * который содержит самую базовую функциональность, необходимую
 * всем обработчикам.
 */
class connection_handler_t
	: public std::enable_shared_from_this< connection_handler_t >
{
public:
	//! Статус обработчика соединения.
	enum class status_t
	{
		//! Обработчик активен, поэтому имеет право обрабатывать
		//! результаты операций ввода-вывода.
		active,
		//! Обработчик был изъят и/или заменен другим обработчиком,
		//! поэтому он не имеет права обрабатывать результаты
		//! операций ввода-вывода.
		released
	};

protected:
	/*!
	 * @brief Индикатор того, что можно выпускать исключения наружу.
	 *
	 * Специальный тип, который означает, что метод/лямбда работает внутри
	 * блока try/catch и, поэтому, может выпускать исключения наружу.
	 *
	 * Экземпляр создается внутри обертки wrap_action_and_handle_exceptions
	 * и передается аргументом в лямбду, которая является параметром для
	 * wrap_action_and_handle_exceptions.
	 */
	using can_throw_t = ::arataga::utils::can_throw_t;

	//! Контекст, в рамках которого обрабатывается соединение.
	handler_context_holder_t m_ctx;

	//! Идентификатор данного соединения.
	handler_context_t::connection_id_t m_id;

	//! Само соединение с клиентом, которое должно обрабатываться.
	asio::ip::tcp::socket m_connection;

	//! Статус обработчика.
	status_t m_status;

	/*!
	 * @name Методы, внутри которых возможно удаление текущего обработчика.
	 * @{
	 */
	virtual void
	on_start_impl( delete_protector_t ) = 0;

	virtual void
	on_timer_impl( delete_protector_t ) = 0;
	/*!
	 * @}
	 */

	[[nodiscard]]
	handler_context_t &
	context() noexcept { return m_ctx.ctx(); }

	/*!
	 * @brief Заменить обработчик соединения на новый.
	 */
	template< typename New_Handler_Factory >
	void
	replace_handler(
		delete_protector_t delete_protector,
		can_throw_t can_throw,
		New_Handler_Factory && new_handler_factory )
	{
		// Если при замене обработчика возникает исключение, то
		// нам не остается больше ничего, кроме принудительного
		// изъятия старого обработчика.
		// Это касается и проблем при создании нового обработчика.
		// Т.е. если new_handler_factory бросит исключение, то
		// текущий обработчик уже может находится в неверном состоянии и
		// продолжать работу не сможет. Поэтому его можно только удалить.
		// Ловим только исключения, производные от std::exception,
		// все остальное пусть приводит к краху приложения.
		[&]() noexcept {
			NOEXCEPT_CTCHECK_STATIC_ASSERT_NOEXCEPT(
					handler_context_holder_t{ m_ctx } );

			// Делаем копию handler_context_holder, т.к. в процессе работы
			// new_handler_factory значение m_ctx может стать пустым.
			handler_context_holder_t ctx_holder = m_ctx;
			try
			{
				connection_handler_shptr_t new_handler = new_handler_factory(
						can_throw );

				ctx_holder.ctx().replace_connection_handler(
						delete_protector,
						m_id,
						std::move(new_handler) );
			}
			catch( const std::exception & x )
			{
				// Исключения, которые могут возникнуть при логировании
				// подавляем.
				try
				{
					::arataga::logging::wrap_logging(
							proxy_logging_mode,
							spdlog::level::err,
							[this, &ctx_holder, &x]( auto level )
							{
								ctx_holder.ctx().log_message_for_connection(
										m_id,
										level,
										x.what() );
							} );
				}
				catch( ... ) {}

				NOEXCEPT_CTCHECK_ENSURE_NOEXCEPT_STATEMENT(
						ctx_holder.ctx().remove_connection_handler(
								delete_protector,
								m_id,
								remove_reason_t::unexpected_and_unsupported_case )
				);
			}
		}();
	}

	//! Удалить обработчик вообще.
	void
	remove_handler(
		delete_protector_t delete_protector,
		remove_reason_t remove_reason )
	{
		context().remove_connection_handler(
				delete_protector, m_id, remove_reason );
	}

	// ПРИМЕЧАНИЕ! Этот метод должен вызываться из
	// logging::wrap_logging.
	void
	log_message_for_connection(
		can_throw_t /*can_throw*/,
		::arataga::logging::processed_log_level_t level,
		std::string_view message )
	{
		context().log_message_for_connection( m_id, level, message ); 
	}

	void
	log_and_remove_connection_on_io_error(
		delete_protector_t delete_protector,
		can_throw_t can_throw,
		const asio::error_code & ec,
		std::string_view operation_description )
	{
		// Логируем ошибку только если это не operation_aborted.
		if( asio::error::operation_aborted != ec )
		{
			::arataga::logging::wrap_logging(
					proxy_logging_mode,
					spdlog::level::warn,
					[&]( auto level )
					{
						log_message_for_connection(
								can_throw,
								level,
								fmt::format( "IO-error on {}: {}",
										operation_description, ec.message() ) );
					} );
		}

		remove_handler( delete_protector, remove_reason_t::io_error );
	}

	void
	log_and_remove_connection(
		delete_protector_t delete_protector,
		can_throw_t can_throw,
		remove_reason_t reason,
		spdlog::level::level_enum level,
		std::string_view description )
	{
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				level,
				[this, can_throw, description]( auto level )
				{
					log_message_for_connection(
							can_throw,
							level,
							description );
				} );

		remove_handler( delete_protector, reason );
	}

	template< typename Action >
	void
	wrap_action_and_handle_exceptions(
		delete_protector_t delete_protector,
		Action && action )
	{
		try
		{
			::arataga::utils::exception_handling_context_t ctx;

			action( delete_protector, ctx.make_can_throw_marker() );
		}
		catch( const std::exception & x )
		{
			// Нужно ловить и проглатывать исключения, которые
			// могут выскочить уже внутри catch.
			try
			{
				::arataga::utils::exception_handling_context_t ctx;

				// В случае возникновения исключения продолжать работу нельзя.
				log_and_remove_connection(
						delete_protector,
						// Здесь явно передаем can_throw потому, что нет
						// смысла ловить и подавлять исключения, которые
						// могут возникнуть при выполнении этих действий.
						ctx.make_can_throw_marker(),
						remove_reason_t::unhandled_exception,
						spdlog::level::err,
						fmt::format( "exception caught: {}", x.what() )
					);
			}
			catch( ... ) {}
		}
		catch( ... )
		{
			// Нужно ловить и проглатывать исключения, которые
			// могут выскочить уже внутри catch.
			try
			{
				::arataga::utils::exception_handling_context_t ctx;

				log_and_remove_connection(
						delete_protector,
						// Здесь явно передаем can_throw потому, что нет
						// смысла ловить и подавлять исключения, которые
						// могут возникнуть при выполнении этих действий.
						ctx.make_can_throw_marker(),
						remove_reason_t::unhandled_exception,
						spdlog::level::err, "unknown exception caught" );
			}
			catch( ... ) {}
		}
	}

	template< typename... Args >
	friend struct completion_handler_maker_t;

	/*!
	 * @brief Вспомогательный класс для создания коллбэка для
	 * обработчика завершения операции ввода-вывода.
	 *
	 * Особенность completion-handler-ов в том, что они могут
	 * быть вызываны уже после того, как connection-handler перестал
	 * быть актуальным и был заменен новым connection-handler-ом.
	 * В такой ситуации completion-handler не должен выполнять свою
	 * работу.
	 *
	 * Для этого нужно проверить статус connection-handler-а и разрешить
	 * работу completion-handler-а только если этот статус равен
	 * status_t::active. В остальных случаях completion-handler
	 * должен сразу же завершить свою работу.
	 *
	 * Поскольку создается много разных completion-handler-ов, то
	 * невыгодно повторять эти проверки в каждом из них вручную.
	 * Вместо этого используется следующий подход: программист
	 * пишет свой completion-handler в виде лямбды, затем эта
	 * лямбда оборачивается в другую лямбду, которая и отдается
	 * в Asio. Эта лямбда-обертка как раз и делает проверку status-а.
	 * Если status равен status_t::active, то оригинальная, заданная
	 * пользователем лямбда вызывается.
	 *
	 * Класс completion_handler_maker_t является частью механизма
	 * создания лямбды-обертки.
	 *
	 * Этот механизм двушаговый, т.к. нужно уметь создавать
	 * completion-handler-ы с разными сигнатурами. Поэтому на первом
	 * шаге создается экземпляр completion_handler_maker_t, параметрами
	 * шаблона которого будут типы аргументов для completion-handler-а.
	 * А на втором шаге у созданного экземпляра вызывается метод
	 * make_handler, в который отдается уже актуальный completion-handler
	 * в виде функтора/лямбды.
	 *
	 * @attention
	 * Первым аргументом актуального compltion-handler-а будет
	 * значение типа delete_protector_t. За ним будет идти аргумент
	 * can_throw_t. Далее будут следовать аргументы типов @a Args.
	 *
	 * @note
	 * Первоначально обертка, которая создавалась в методе make_handler
	 * не занималась перехватом и обработкой исключений. Но затем
	 * внутри этой обертки стал использоваться wrap_action_and_handle_exceptions,
	 * поэтому сейчас актуальный completion-handler вызывается внутри
	 * блока try.
	 */
	template< typename... Args >
	struct completion_handler_maker_t
	{
		connection_handler_shptr_t m_handler;

		completion_handler_maker_t(
			connection_handler_shptr_t handler )
			:	m_handler{ std::move(handler) }
		{}

		template< typename Completion >
		[[nodiscard]]
		auto
		make_handler( Completion && completion ) &&
		{
			return
				[handler = std::move(m_handler),
					completion_func = std::move(completion)]
				( Args ...args ) mutable
				{
					if( status_t::active == handler->m_status )
					{
						details::delete_protector_maker_t protector{ handler };
						handler->wrap_action_and_handle_exceptions(
								protector.make(),
								[&](
									delete_protector_t delete_protector,
									can_throw_t can_throw )
								{
									completion_func(
											delete_protector,
											can_throw,
											std::forward<Args>(args)... );
								} );
					}
				};
		}
	};

	//! Выполнить первый шаг операции создания completion-handler-а.
	/*!
	 * Пример использования:
	 * @code
	 * with<const asio::error_code &, std::size_t>().make_handler(
	 * 	[this]( delete_protector_t delete_protector,
	 * 		can_throw_t can_throw,
	 * 		const asio::error_code & ec,
	 * 		std::size_t bytes_transferred )
	 * 	{
	 * 		... // Код обработчика.
	 * 	});
	 * @endcode
	 */
	template< typename... Args >
	completion_handler_maker_t< Args... >
	with() noexcept
	{
		return { shared_from_this() };
	}

	template< typename Completion >
	[[nodiscard]]
	auto
	make_read_write_completion_handler(
		// ВНИМАНИЕ: этот аргумент должен прожить до конца работы
		// completion-handler-а. Т.е. это должен быть строковый литерал.
		std::string_view op_name,
		Completion && completion )
	{
		return with<const asio::error_code &, std::size_t>()
			.make_handler(
				// Нет необходимости вызывать shared_from_this, т.к. это
				// уже делает make_io_completion_handler.
				[this, op_name, completion_func = std::move(completion)](
				delete_protector_t delete_protector,
				can_throw_t can_throw,
				const asio::error_code & ec,
				std::size_t bytes_transferred ) mutable
				{
					if( ec )
						log_and_remove_connection_on_io_error(
								delete_protector,
								can_throw, ec, op_name );
					else
						completion_func(
								delete_protector,
								can_throw, bytes_transferred );
				} );
	}

	template<
		typename Buffer,
		typename Completion >
	void
	read_some(
		can_throw_t /*can_throw*/,
		asio::ip::tcp::socket & connection,
		Buffer & buffer,
		Completion && completion )
	{
		connection.async_read_some(
				buffer.asio_buffer(),
				make_read_write_completion_handler(
					"read",
					[completion_func = std::move(completion), &buffer](
						delete_protector_t delete_protector,
						can_throw_t can_throw,
						std::size_t bytes_transferred )
					{
						buffer.increment_bytes_read( bytes_transferred );
						completion_func( delete_protector, can_throw );
					} )
		);
	}

	template<
		typename Buffer,
		typename Completion >
	void
	write_whole(
		can_throw_t /*can_throw*/,
		asio::ip::tcp::socket & connection,
		Buffer & buffer,
		Completion && completion )
	{
		asio::async_write(
				connection,
				buffer.asio_buffer(),
				make_read_write_completion_handler(
					"write",
					[&buffer, completion_func = std::move(completion)](
						delete_protector_t delete_protector,
						can_throw_t can_throw,
						std::size_t bytes_transferred ) mutable
					{
						buffer.increment_bytes_written( bytes_transferred );
						completion_func( delete_protector, can_throw );
					} )
		);
	}

public:
	connection_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection );

	virtual ~connection_handler_t();

	void
	on_start();

	void
	on_timer();

	[[nodiscard]]
	virtual std::string_view
	name() const noexcept = 0;

	// Реализация по умолчанию закрывает m_connection, если
	// m_connection еще не закрыт.
	// Так же статус обработчика меняется на released.
	virtual void
	release() noexcept;
};

} /* namespace arataga::acl_handler */

