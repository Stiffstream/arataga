/*!
 * @file
 * @brief Interfaces for connection_handlers.
 */

#pragma once

#include <arataga/acl_handler/sequence_number.hpp>

#include <arataga/utils/can_throw.hpp>
#include <arataga/utils/string_literal.hpp>

#include <arataga/config.hpp>

#include <arataga/logging/wrap_logging.hpp>

#include <arataga/nothrow_block/macros.hpp>

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
 * @brief An interface of object for accessing the config.
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
//! Enumeration for connection-handler removal reason.
enum remove_reason_t
{
	//! Normal completion of connection serving.
	normal_completion,
	//! I/O error detected.
	io_error,
	//! The current operation timed-out.
	current_operation_timed_out,
	//! Unsupported protocol detected.
	unsupported_protocol,
	//! Some protocol-related error. For example, an unsupported protocol
	//! version detected.
	protocol_error,
	//! Some unexpected case that can't be correctly handled.
	unexpected_and_unsupported_case,
	//! There is no activity in the connection for too long time.
	no_activity_for_too_long,
	//! The current operation was cancelled from outside.
	current_operation_canceled,
	//! A uncaught exception fron connection-handled detected.
	unhandled_exception,
	//! The required IP-version can't be used.
	//! For example, an attempt to connect IPv6 address from IPv4 address.
	ip_version_mismatch,
	//! The user has no required permissions.
	access_denied,
	//! The failure of target domain name resolution.
	unresolved_target,
	//! The connection to the target host was broken.
	target_end_broken,
	//! The connection from the user was broken.
	user_end_broken,
	//! HTTP-reposnse was received before the completion of outgoing
	//! HTTP-request.
	http_response_before_completion_of_http_request,
	//! The connection from the user was closed by the user-end.
	user_end_closed_by_client,
	//! The user didn't send a new incoming HTTP-request.
	http_no_incoming_request
};

[[nodiscard]]
inline constexpr arataga::utils::string_literal_t
to_string_literal( remove_reason_t reason )
{
	using namespace arataga::utils::string_literals;

	auto result = "<unknown>"_static_str;
	switch( reason )
	{
	case remove_reason_t::normal_completion:
		result = "normal_completion"_static_str;
	break;

	case remove_reason_t::io_error:
		result = "io_error"_static_str;
	break;

	case remove_reason_t::current_operation_timed_out:
		result = "current_operation_timed_out"_static_str;
	break;

	case remove_reason_t::unsupported_protocol:
		result = "unsupported_protocol"_static_str;
	break;

	case remove_reason_t::protocol_error:
		result = "protocol_error"_static_str;
	break;

	case remove_reason_t::unexpected_and_unsupported_case:
		result = "unexpected_and_unsupported_case"_static_str;
	break;

	case remove_reason_t::no_activity_for_too_long:
		result = "no_activity_for_too_long"_static_str;
	break;

	case remove_reason_t::current_operation_canceled:
		result = "current_operation_canceled"_static_str;
	break;

	case remove_reason_t::unhandled_exception:
		result = "unhandled_exception"_static_str;
	break;

	case remove_reason_t::ip_version_mismatch:
		result = "ip_version_mismatch"_static_str;
	break;

	case remove_reason_t::access_denied:
		result = "access_denied"_static_str;
	break;

	case remove_reason_t::unresolved_target:
		result = "unresolved_target"_static_str;
	break;

	case remove_reason_t::target_end_broken:
		result = "target_end_broken"_static_str;
	break;

	case remove_reason_t::user_end_broken:
		result = "user_end_broken"_static_str;
	break;

	case remove_reason_t::http_response_before_completion_of_http_request:
		result = "http_response_before_completion_of_http_request"_static_str;
	break;

	case remove_reason_t::user_end_closed_by_client:
		result = "user_end_closed_by_client"_static_str;
	break;

	case remove_reason_t::http_no_incoming_request:
		result = "http_no_incoming_request"_static_str;
	break;
	}

	return result;
}

inline std::ostream &
operator<<( std::ostream & to, remove_reason_t reason )
{
	return (to << to_string_literal(reason));
}

// The definition is going below.
class connection_handler_t;

//
// connection_handler_shptr_t
//
/*!
 * @brief An alias for shared_ptr to connection_handler.
 */
using connection_handler_shptr_t = std::shared_ptr< connection_handler_t >;

//
// traffic_limiter_t
//
/*!
 * @brief An interface for object that limits the bandwidth.
 *
 * An implementation of that interface should clean all resources
 * in its destructor.
 */
class traffic_limiter_t
{
public:
	enum class direction_t { from_user, from_target };

	/*!
	 * @brief The result of asking a quote for reading incoming
	 * data on the current turn.
	 *
	 * If the direction can be read then m_capacity will contain
	 * an enabled amount of data to be read. After the completion
	 * of the read operation method release() should be called
	 * for reserved_capacity_t object.
	 */
	struct reserved_capacity_t
	{
		std::size_t m_capacity;
		sequence_number_t m_sequence_number;

		//! The method for registering the result of I/O operation
		//! in traffic_limiter.
		/*!
		 * This method analyses the error code and, if that code is not 0,
		 * assumes that 0 bytes are read.
		 *
		 * @attention
		 * This method must be called after the completion of I/O operation.
		 * Otherwise the reserved capacity will remain reserved till the
		 * end of the current turn.
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

	// Can return 0.
	// In that case attempts of reading data should be suspended
	// until the next turn.
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
 * @brief An alias for unique_ptr to traffic_limiter.
 */
using traffic_limiter_unique_ptr_t =
	std::unique_ptr< traffic_limiter_t >;

namespace dns_resolving
{

//! The result of successful DNS-resolving.
struct hostname_found_t
{
	//! IP-address for the domain name.
	asio::ip::address m_ip;
};

//! The result of failed DNS-resolving.
struct hostname_not_found_t
{
	//! Textual description of the failure.
	std::string m_error_desc;
};

//! Type for DNS-resolving result.
using hostname_result_t = std::variant<
		hostname_found_t,
		hostname_not_found_t
	>;

//! Type of a functor that should be called after the completion
//! of DNS-resolving.
using hostname_result_handler_t =
	std::function< void(const hostname_result_t &) >;

} /* namespace dns_resolving */

namespace authentification
{

//! Parameters for an authentification request.
struct request_params_t
{
	asio::ip::address_v4 m_user_ip;
	std::optional< std::string > m_username;
	std::optional< std::string > m_password;
	std::string m_target_host;
	std::uint16_t m_target_port;
};

//! Enumeration of reasons for failed authentification.
enum class failure_reason_t
{
	unknown_user,
	target_blocked
};

[[nodiscard]]
inline constexpr arataga::utils::string_literal_t
to_string_literal( failure_reason_t reason )
{
	using namespace arataga::utils::string_literals;

	switch( reason )
	{
	case failure_reason_t::unknown_user:
		return "user unknown"_static_str;
	case failure_reason_t::target_blocked:
		return "target is blocked for user"_static_str;
	}

	return "<unknown>"_static_str;
}

//! Type of negative authentification result.
struct failure_t
{
	failure_reason_t m_reason;
};

//! Type of positive authentification result.
struct success_t
{
	//! Actual traffic limiter for the new connection.
	traffic_limiter_unique_ptr_t m_traffic_limiter;
};

//! Type for authentification result.
using result_t = std::variant< failure_t, success_t >;

//! Type of a functor to be called after the completion of
//! user authentification.
using result_handler_t =
	// The result is passed by value to enable to borrow
	// moveable only values.
	std::function< void(result_t) >;

} /* namespace dns_resolving */

//
// connection_type_t
//
/*!
 * @brief Enumeration of various types of connections.
 */
enum class connection_type_t
{
	//! Type of the connection is not known yet.
	/*!
	 * This type should be used for stats of total number of connections.
	 */
	generic,
	//! The connection uses SOCKS5 protocol.
	socks5,
	//! The connection uses HTTP protocol.
	http
};

namespace details {

class delete_protector_maker_t;

} /* namespace details */

//
// delete_protector_t
//
/*!
 * @brief A special marker that tells that connection_handler is
 * protected from the deletion and it's safe to replace the current
 * handler by a new one.
 *
 * An instance of delete_protector does nothing. But it presence
 * tells that there is an instance of
 * details::delete_protector_maker_t somewhere at the stack. And
 * that delete_protector_maker_t defends the connection_handler
 * from early deletion.
 *
 * The necessity of that class goes from the fact that connection_handler calls
 * remove_connection_handler and replace_connection_handler from inside of own
 * methods. As result of remove_connection_handler and
 * replace_connection_handler the current handler can be deleted and this
 * invalidates the `this` value. This can lead to use-after-free errors (for
 * example if some non-static method will be acidentially called after the
 * return from remove_connection_handler/replace_connection_handler).
 *
 * For protection from use-after-free error a scheme with additional
 * connection_handler_shptr_t is used. This additional instance is created on
 * the stack and only then methods like
 * remove_connection_handler/replace_connection_handler are called.  This
 * additional instance protects the current handler from the deletion.
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
 * @brief An interface of objects that holds a context in that
 * user's connections are handled.
 */
class handler_context_t
{
public:
	virtual ~handler_context_t();

	//! Type of connection ID inside that context.
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

	// NOTE: this method should be called inside logging::wrap_logging!
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
 * @brief A special class that guarantees that handler_context
 * will exist until someone holds a smart reference to it.
 *
 * There a danger in the use of Asio's async operations: completion
 * handler for an operation can be called after the destruction of
 * handler_context. In that case connection_handler will hold a
 * dangled reference to handler_context. Any attempt to use
 * that reference (a call to log_message_for_connection for example)
 * will lead to undefined behaviour.
 *
 * To avoid that class handler_context_holder_t plays a role of
 * a smart reference (or smart pointer) to handler_context.
 * If a connection_handler holds an instance of
 * handler_context_holder_t then it guarantees that handler_context
 * will live even if handler_context itself has finished its work.
 */
class handler_context_holder_t
{
	//! A smart pointer to the object that holds handler_context.
	so_5::agent_ref_t m_holder_agent;

	//! A reference to the actual handler_context.
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

class connection_handler_t;

//
// connection_remover_t
//
// NOTE: the implementation of connection_remover_t will go
// after the declaration of connection_handler_t.
/*!
 * @brief Helper that removes a connection in the destructor.
 *
 * This class is intended to make the removal of a connection more robust in
 * the case of exceptions. Sometimes it is necessary to do several actions just
 * before removal of the connection (like logging, for example). Some of those
 * actions can throw. But the connection has to be removed even in the case of
 * an exception. Do guarantee that an instance of connection_remover_t has to
 * be used. For example:
 *
 * @code
 * if( some_error_condition )
 * {
 * 	connection_remover_t remover{
 * 			*this, delete_protector, remover_reason_t::protocol_error
 * 	};
 *
 * 	// Connection will be closed even if easy_log_for_connection throws.
 * 	easy_log_for_connection(
 * 			can_throw,
 * 			spdlog::level::warn,
 * 			format_string{ "unexpected message: {}" },
 * 			message_type );
 * }
 * @endcode
 *
 * @since v.0.5.2
 */
class connection_remover_t
{
	connection_handler_t & m_handler;
	const delete_protector_t m_delete_protector;
	const remove_reason_t m_reason;

public:
	connection_remover_t(
		connection_handler_t & handler,
		delete_protector_t delete_protector,
		remove_reason_t remove_reason ) noexcept;
	~connection_remover_t() noexcept;

	// NOTE: this class isn't Copyable, nor Moveable.
	connection_remover_t( const connection_remover_t & ) = delete;
	connection_remover_t &
	operator=( const connection_remover_t & ) = delete;

	connection_remover_t( connection_remover_t && ) = delete;
	connection_remover_t &
	operator=( connection_remover_t && ) = delete;
};

//
// connection_handler_t
//
/*!
 * @brief A base type for connection_handler.
 *
 * This type not only defines an interface of connection_handler
 * but also contains a basic functionality necessary for all
 * connection_handler implementations.
 */
class connection_handler_t
	: public std::enable_shared_from_this< connection_handler_t >
{
	friend class connection_remover_t;

public:
	//! Handler status.
	enum class status_t
	{
		//! Handler is active. It can handle the results of I/O operations.
		active,
		//! Handler is released. It was removed or replaced by another
		//! handler. Because of that it can't handle the results
		//! of I/O operations.
		released
	};

private:
	//! Remove the handler.
	/*!
	 * @note
	 * Since v.0.5.2 this method is private. So, only connection_remover_t
	 * can access it. This method is also noexcept now.
	 */
	void
	remove_handler(
		delete_protector_t delete_protector,
		remove_reason_t remove_reason ) noexcept
	{
		NOEXCEPT_CTCHECK_ENSURE_NOEXCEPT_STATEMENT(
			context().remove_connection_handler(
					delete_protector, m_id, remove_reason )
		);
	}

protected:
	/*!
	 * @brief A special indicator that tells that exceptions can go out.
	 *
	 * This indicator tells a method/lambda that it's invoked inside
	 * try/catch block and throwing of an exception is permited.
	 *
	 * An instance is created inside wrap_action_and_handle_exceptions()
	 * and passed as a parameter to lambda-argument of
	 * wrap_action_and_handle_exceptions().
	 */
	using can_throw_t = ::arataga::utils::can_throw_t;

	//! Context for connection handler.
	handler_context_holder_t m_ctx;

	//! ID for the connection.
	handler_context_t::connection_id_t m_id;

	//! The connection with the client.
	/*!
	 * That is the socked accepted by ACL.
	 */
	asio::ip::tcp::socket m_connection;

	//! Handler status.
	status_t m_status;

	/*!
	 * @name Methods inside those the handler can be removed/replaced.
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
	 * @brief Replace the handler to a new one.
	 */
	template< typename New_Handler_Factory >
	void
	replace_handler(
		delete_protector_t delete_protector,
		can_throw_t can_throw,
		New_Handler_Factory && new_handler_factory )
	{
		// If there will be an exception we'll have no choice except
		// the removement of the old handler.
		//
		// The same picture is also for problems with the exceptions
		// during the creation of a new handler. The old handler can
		// be in invalid state when new_handler_factory throws. So we can
		// only delete the old handler.
		//
		// Will catch only exceptions derived from std::exception.
		// All other types of exception will crash the whole app.
		[&]() noexcept {
			NOEXCEPT_CTCHECK_STATIC_ASSERT_NOEXCEPT(
					handler_context_holder_t{ m_ctx } );

			// Make a copy of handler_context_holder because as
			// the result of new_handler_factory invocation the m_ctx
			// can become empty.
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
				// Ignore exceptions that can be thrown during the logging.
				ARATAGA_NOTHROW_BLOCK_BEGIN()
					ARATAGA_NOTHROW_BLOCK_STAGE(log_exception)

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
				ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_IGNORE)

				NOEXCEPT_CTCHECK_ENSURE_NOEXCEPT_STATEMENT(
						ctx_holder.ctx().remove_connection_handler(
								delete_protector,
								m_id,
								remove_reason_t::unexpected_and_unsupported_case )
				);
			}
		}();
	}

	// NOTE: this method should be called from inside logging::wrap_logging.
	void
	log_message_for_connection(
		can_throw_t /*can_throw*/,
		::arataga::logging::processed_log_level_t level,
		std::string_view message )
	{
		context().log_message_for_connection( m_id, level, message ); 
	}

	// Simple logging for the case when log message is a string literal.
	void
	easy_log_for_connection(
		can_throw_t can_throw,
		spdlog::level::level_enum level,
		arataga::utils::string_literal_t description )
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
	}

	// Helper data structure to be used like strong typedef in case like that:
	//
	// easy_log_for_connection(
	// 	can_throw,
	// 	spdlog::level::warn,
	// 	format_string{ "unexpected result: {}" },
	// 	result );
	//
	struct format_string
	{
		// NOTE: expected to be not-null.
		const char * m_format_str;
	};

	// Simple logging for the case when log message has to be constructed
	// from format string and several arguments.
	template< typename... Args >
	void
	easy_log_for_connection(
		can_throw_t can_throw,
		spdlog::level::level_enum level,
		format_string format,
		Args && ...format_args )
	{
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				level,
				[&]( auto actual_level )
				{
					log_message_for_connection(
							can_throw,
							actual_level,
							fmt::format(
									format.m_format_str,
									std::forward<Args>(format_args)... ) );
				} );
	}

	void
	log_on_io_error(
		can_throw_t can_throw,
		const asio::error_code & ec,
		std::string_view operation_description )
	{
		// Should log the error except operation_aborted (this error is
		// expected).
		if( asio::error::operation_aborted != ec )
		{
			easy_log_for_connection(
					can_throw,
					spdlog::level::warn,
					format_string{ "IO-error on {}: {}" },
					operation_description, ec.message() );
		}
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
			// We have to catch and suppress exceptions from here.
			ARATAGA_NOTHROW_BLOCK_BEGIN()
				ARATAGA_NOTHROW_BLOCK_STAGE(log_and_remove_connection)

				connection_remover_t remover{
						*this,
						delete_protector,
						remove_reason_t::unhandled_exception
				};

				::arataga::utils::exception_handling_context_t ctx;

				easy_log_for_connection(
						ctx.make_can_throw_marker(),
						spdlog::level::err,
						format_string{ "exception caught: {}" },
						x.what() );
			ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_IGNORE)
		}
		catch( ... )
		{
			// We have to catch and suppress exceptions from here.
			ARATAGA_NOTHROW_BLOCK_BEGIN()
				ARATAGA_NOTHROW_BLOCK_STAGE(
						log_and_remove_connection_on_unknow_exception)

				connection_remover_t remover{
						*this,
						delete_protector,
						remove_reason_t::unhandled_exception
				};

				::arataga::utils::exception_handling_context_t ctx;

				using namespace arataga::utils::string_literals;
				easy_log_for_connection(
						ctx.make_can_throw_marker(),
						spdlog::level::err,
						"unknown exception caught"_static_str );
			ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_IGNORE);
		}
	}

	template< typename... Args >
	friend struct completion_handler_maker_t;

	/*!
	 * @brief A helper class for the creation of a callback
	 * for completion handler of an I/O operation.
	 *
	 * There is a tricky moment related to completion-handlers:
	 * they can be called after the removal of the coresponding
	 * connection_handler. In that case a completion-handler
	 * shouldn't do its work.
	 *
	 * The connection_handler's status should be checked at the
	 * beginning of completion-handler. The work should be done only
	 * if the connection_handler is still active (the status is
	 * status_t::active).
	 * 
	 * Because there ara many different completion-handlers it's
	 * boring task to write that check in every of handlers. Another
	 * approach is used here: a programmer writes completion-handler
	 * in the form of a lambda. This lambda then wrapped into another
	 * lambda-function that is passed to Asio. This wrapper perform
	 * necessary status check and calls programmer's lambda if
	 * the status allows process the result of I/O operation.
	 *
	 * The class completion_handler_maker_t is a part of process
	 * of creation of the wrapped mentioned above.
	 *
	 * This is two-step process, because we have to create
	 * completion-handlers with different signatures.
	 *
	 * An instance of completion_handler_maker_t is created on the first step.
	 * The template parameters for it will be types of arguments for
	 * the completion-handler.
	 *
	 * Method make_handler is called on the second step. That method
	 * gets an actual completion-handler lambda as an argument and
	 * returns a proper wrapper.
	 *
	 * @attention
	 * This first parameter for user-provided completion-handler will be
	 * a value of delete_protector_t type. Then there will be a value
	 * of type can_throw_t. Then there will be parameters of types @a Args.
	 *
	 * @note
	 * Initialy a wrapper, created inside make_handler() method, doesn't
	 * catch exceptions. But then wrap_action_and_handle_exceptions() was
	 * used inside so now user-provided completion-handler is called
	 * from try...catch block.
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

	//! Do the first step of completion-handler creation.
	/*!
	 * Usage example:
	 * @code
	 * with<const asio::error_code &, std::size_t>().make_handler(
	 * 	[this]( delete_protector_t delete_protector,
	 * 		can_throw_t can_throw,
	 * 		const asio::error_code & ec,
	 * 		std::size_t bytes_transferred )
	 * 	{
	 * 		... // Handler code.
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
		// Require string-literal because this value has to be valid
		// until the end of completion-handler work.
		arataga::utils::string_literal_t op_name,
		Completion && completion )
	{
		return with<const asio::error_code &, std::size_t>()
			.make_handler(
				// There is no sense to call shared_from_this because
				// it's already done by make_io_completion_handler.
				[this, op_name, completion_func = std::move(completion)](
				delete_protector_t delete_protector,
				can_throw_t can_throw,
				const asio::error_code & ec,
				std::size_t bytes_transferred ) mutable
				{
					if( ec )
					{
						// Connection has to be removed.
						connection_remover_t remover{
								*this,
								delete_protector,
								remove_reason_t::io_error
						};

						log_on_io_error( can_throw, ec, op_name );
					}
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
		using namespace arataga::utils::string_literals;

		connection.async_read_some(
				buffer.asio_buffer(),
				make_read_write_completion_handler(
					"read"_static_str,
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
		using namespace arataga::utils::string_literals;

		asio::async_write(
				connection,
				buffer.asio_buffer(),
				make_read_write_completion_handler(
					"write"_static_str,
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
	virtual arataga::utils::string_literal_t
	name() const noexcept = 0;

	// The default implementation closes m_connection if it is not closed yet.
	// The status is changed to status_t::released.
	virtual void
	release() noexcept;
};

//
// connection_remover_t implementation
//
inline
connection_remover_t::connection_remover_t(
	connection_handler_t & handler,
	delete_protector_t delete_protector,
	remove_reason_t remove_reason ) noexcept
	:	m_handler{ handler }
	,	m_delete_protector{ delete_protector }
	,	m_reason{ remove_reason }
{}

inline
connection_remover_t::~connection_remover_t() noexcept
{
	m_handler.remove_handler( m_delete_protector, m_reason );
}

} /* namespace arataga::acl_handler */

