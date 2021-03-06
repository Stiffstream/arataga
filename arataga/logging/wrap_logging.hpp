/*!
 * @file
 * @brief Helpers for logging.
 */

#pragma once

#include <arataga/logging/stats_counters.hpp>

namespace arataga
{

namespace logging
{

namespace impl
{

/*!
 * @brief Setup a logger for the whole application.
 *
 * It's assumed that this function is called only once at the
 * beginning of the application. And then @a logger will be used
 * until the finish of the application.
 */
void
setup_logger( std::shared_ptr< spdlog::logger > logger ) noexcept;

/*!
 * @brief Remove the logger previously set via setup_logger.
 *
 * It's assumed that this function is called at the end of the
 * application lifetime and logger is no more needed.
 */
void
remove_logger() noexcept;

/*!
 * @brief Get access to logger that previously set via setup_logger.
 *
 * It's a UB if this function is called after remove_logger().
 */
[[nodiscard]]
spdlog::logger &
logger() noexcept;

/*!
 * @brief Check a possibilty to log a message with specified
 * severity level.
 */
[[nodiscard]]
inline bool
should_log( spdlog::level::level_enum level ) noexcept
{
	return logger().should_log( level );
}

/*!
 * @brief Helper for count exceptions during logging.
 *
 * @since v.0.4.4
 */
class exception_count_guard_t
{
	bool m_committed{ false };

public:
	exception_count_guard_t() = default;
	exception_count_guard_t( const exception_count_guard_t & ) = delete;
	exception_count_guard_t( exception_count_guard_t && ) = delete;

	~exception_count_guard_t() noexcept
	{
		if( !m_committed )
			increment_count_of_exceptions_during_logging();
	}

	void
	commit() noexcept { m_committed = true; }
};

} /* namespace impl */

/*!
 * @brief Helper class for setting/removing logger in RAII style.
 *
 * Calls impl::setup_logger() in the constructor, then impl::remove_logger()
 * in the destructor.
 *
 * Usage example:
 * @code
 * int main(int argc, char ** argv)
 * {
 * 	... // Parsing of command-line args.
 * 	arataga::logging::logger_holder_t logger_holder{
 * 		spdlog::default_logger()
 * 	};
 * 	... // All remaining actions of the application.
 * }
 * @endcode
 */
class logger_holder_t
{
public:
	logger_holder_t( std::shared_ptr< spdlog::logger > logger ) noexcept
	{
		impl::setup_logger( std::move(logger) );
	}

	~logger_holder_t()
	{
		impl::remove_logger();
	}
};

/*!
 * @brief Marker that tells that logging should be performed
 * via the main logger.
 */
struct direct_logging_marker_t {};

/*!
 * @brief Marker that tells that logging should be performed
 * via a proxy-object.
 */
struct proxy_logging_marker_t {};

/*!
 * @brief A special wrapper around logging-level that tells that
 * logging is performed from wrap_logging helper.
 */
class processed_log_level_t
{
	spdlog::level::level_enum m_level;

public:
	explicit processed_log_level_t(
		spdlog::level::level_enum level )
		:	m_level{ level }
	{}

	[[nodiscard]]
	auto
	value() const noexcept { return m_level; }

	[[nodiscard]]
	operator spdlog::level::level_enum() const noexcept { return value(); }
};

/*!
 * @brief Perform logging via logger object directly.
 *
 * The functor @a action is called only if @a level is enabled
 * for logging.
 *
 * The functor @a action should have the following format:
 * @code
 * void(spdlog::logger &, processed_log_level_t);
 * @endcode
 */
template< typename Logging_Action >
void
wrap_logging(
	direct_logging_marker_t,
	spdlog::level::level_enum level,
	Logging_Action && action )
{
	impl::increment_counters_if_neccessary( level );
	if( impl::should_log( level ) )
	{
		// NOTE: action can throw. Exceptions should be counted.
		impl::exception_count_guard_t guard;
		action( impl::logger(), processed_log_level_t{ level } );
		guard.commit();
	}
}

/*!
 * @brief Perform logging via some proxy-object.
 *
 * The functor @a action is called only if @a level is enabled
 * for logging.
 *
 * The functor @a action should have the following format:
 * @code
 * void(processed_log_level_t);
 * @endcode
 */
template< typename Logging_Action >
void
wrap_logging(
	proxy_logging_marker_t,
	spdlog::level::level_enum level,
	Logging_Action && action )
{
	impl::increment_counters_if_neccessary( level );
	if( impl::should_log( level ) )
	{
		// NOTE: action can throw. Exceptions should be counted.
		impl::exception_count_guard_t guard;
		action( processed_log_level_t{ level } );
		guard.commit();
	}
}

} /* namespace logging */

inline constexpr logging::direct_logging_marker_t direct_logging_mode;

inline constexpr logging::proxy_logging_marker_t proxy_logging_mode;

namespace logging::direct_mode
{

template< typename Logging_Action >
void
trace( Logging_Action && action )
{
	wrap_logging( direct_logging_mode, spdlog::level::trace,
			std::forward<Logging_Action>(action) );
}

template< typename Logging_Action >
void
debug( Logging_Action && action )
{
	wrap_logging( direct_logging_mode, spdlog::level::debug,
			std::forward<Logging_Action>(action) );
}

template< typename Logging_Action >
void
info( Logging_Action && action )
{
	wrap_logging( direct_logging_mode, spdlog::level::info,
			std::forward<Logging_Action>(action) );
}

template< typename Logging_Action >
void
warn( Logging_Action && action )
{
	wrap_logging( direct_logging_mode, spdlog::level::warn,
			std::forward<Logging_Action>(action) );
}

template< typename Logging_Action >
void
err( Logging_Action && action )
{
	wrap_logging( direct_logging_mode, spdlog::level::err,
			std::forward<Logging_Action>(action) );
}

template< typename Logging_Action >
void
critical( Logging_Action && action )
{
	wrap_logging( direct_logging_mode, spdlog::level::critical,
			std::forward<Logging_Action>(action) );
}

} /* namespace logging::direct_mode */

namespace logging::proxy_mode
{

template< typename Logging_Action >
void
trace( Logging_Action && action )
{
	wrap_logging( proxy_logging_mode, spdlog::level::trace,
			std::forward<Logging_Action>(action) );
}

template< typename Logging_Action >
void
debug( Logging_Action && action )
{
	wrap_logging( proxy_logging_mode, spdlog::level::debug,
			std::forward<Logging_Action>(action) );
}

template< typename Logging_Action >
void
info( Logging_Action && action )
{
	wrap_logging( proxy_logging_mode, spdlog::level::info,
			std::forward<Logging_Action>(action) );
}

template< typename Logging_Action >
void
warn( Logging_Action && action )
{
	wrap_logging( proxy_logging_mode, spdlog::level::warn,
			std::forward<Logging_Action>(action) );
}

template< typename Logging_Action >
void
err( Logging_Action && action )
{
	wrap_logging( proxy_logging_mode, spdlog::level::err,
			std::forward<Logging_Action>(action) );
}

template< typename Logging_Action >
void
critical( Logging_Action && action )
{
	wrap_logging( proxy_logging_mode, spdlog::level::critical,
			std::forward<Logging_Action>(action) );
}

} /* namespace logging::direct_mode */

} /* namespace arataga */

