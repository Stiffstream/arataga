/*!
 * @file
 * @brief Helpers for logging.
 */

#include <arataga/logging/wrap_logging.hpp>

#include <stdexcept>

namespace arataga::logging
{

namespace impl
{

static std::shared_ptr< spdlog::logger > g_logger;

void
setup_logger( std::shared_ptr< spdlog::logger > logger ) noexcept
{
	g_logger = logger;
}

void
remove_logger() noexcept
{
	g_logger = {};
}

static void
ensure_logger_is_present()
{
	// If there is no logger then there is no sense to work further.
	if( !g_logger )
		throw std::runtime_error( "logger is not set and can't be obtained" );
}

[[nodiscard]]
spdlog::logger &
logger() noexcept
{
	ensure_logger_is_present();

	return *g_logger;
}

} /* namespace impl */

} /* namespace arataga::logging */

