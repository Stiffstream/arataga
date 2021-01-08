/*!
 * @file
 * @brief Вспомогательный метод для выполнения логирования.
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
 * @brief Установить logger, который будет использоваться всем приложением.
 *
 * Предполагается, что вызов этой функции выполняется в начале работы,
 * после того, как обработаны параметры командной строки. После чего
 * @a logger будет использоваться до завершения работы программы.
 */
void
setup_logger( std::shared_ptr< spdlog::logger > logger ) noexcept;

/*!
 * @brief Удалить logger, который ранее был установлен через setup_logger.
 *
 * Предполагается, что вызов этой функции выполняется в конце работы
 * приложения, когда логгер уже никому не нужен.
 */
void
remove_logger() noexcept;

/*!
 * @brief Получить доступ к logger-у, который ранее был установлен
 * через setup_logger.
 */
[[nodiscard]]
spdlog::logger &
logger() noexcept;

/*!
 * @brief Проверить, разрешено ли логирование сообщений с указанным
 * уровнем важности.
 */
[[nodiscard]]
inline bool
should_log( spdlog::level::level_enum level ) noexcept
{
	return logger().should_log( level );
}

} /* namespace impl */

/*!
 * @brief Вспомогательный класс для установки/удаления логгера в RAII стиле.
 *
 * Вызывает impl::setup_logger() в конструкторе и impl::remove_logger()
 * в деструкторе.
 *
 * Пример использования:
 * @code
 * int main(int argc, char ** argv)
 * {
 * 	... // Парсинг аргументов командной строки.
 * 	arataga::logging::logger_holder_t logger_holder{
 * 		spdlog::default_logger()
 * 	};
 * 	... // Остальные действия приложения.
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
 * @brief Маркер, который означает, что логирование должно вестись
 * непосредственно через основной логгер.
 */
struct direct_logging_marker_t {};

/*!
 * @brief Маркер, который означает, что логирование будет выполняться
 * через промежуточный прокси-объект.
 */
struct proxy_logging_marker_t {};

/*!
 * @brief Специальная обертка над уровнем логирования, которая указывает,
 * что логирование ведется внутри вспомогательной функции wrap_logging.
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
 * @brief Выполнить логирование непосредственно через логгер.
 *
 * Функтор @a action вызывается только если разрешено логирование
 * сообщений с уровнем важности @a level.
 *
 * Функтор @a action должен иметь следующий формат:
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
		action( impl::logger(), processed_log_level_t{ level } );
	}
}

/*!
 * @brief Выполнить логирование через какой-то прокси-объект, который
 * уже сам обратиться к логгеру.
 *
 * Функтор @a action вызывается только если разрешено логирование
 * сообщений с уровнем важности @a level.
 *
 * Функтор @a action должен иметь следующий формат:
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
		action( processed_log_level_t{ level } );
	}
}

} /* namespace logging */

inline constexpr logging::direct_logging_marker_t direct_logging_mode;

inline constexpr logging::proxy_logging_marker_t proxy_logging_mode;

} /* namespace arataga */


