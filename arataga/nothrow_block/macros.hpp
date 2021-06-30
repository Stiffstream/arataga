/*!
 * @file
 * @brief Macros for nothrow blocks.
 * @since v.0.4.1
 */

#pragma once

#include <arataga/logging/wrap_logging.hpp>

/*!
 * Starts a new block for catching and suppressing all exceptions.
 *
 * Usage example:
 * @code
 * ARATAGA_NOTHROW_BLOCK_BEGIN()
 * 	... // Some code inside.
 * ARATAGA_NOTHROW_BLOCK_END(JUST_IGNORE)
 * @endcode
 */
#define ARATAGA_NOTHROW_BLOCK_BEGIN() \
{ \
	const char * arataga_nothrow_block_stage__ = nullptr; \
	(void)arataga_nothrow_block_stage__; \
	try \
	{ 

/*!
 * Sets an internal variable. That value will be used later for logging.
 *
 * Usage example:
 * @code
 * ARATAGA_NOTHROW_BLOCK_BEGIN()
 * 	ARATAGA_NOTHROW_BLOCK_STAGE(first_stage)
 * 	... // Some code
 *
 * 	ARATAGA_NOTHROW_BLOCK_STAGE(second_stage)
 * 	... // Some code
 * ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_IGNORE)
 * @endcode
 */
#define ARATAGA_NOTHROW_BLOCK_STAGE(stage_name) \
	arataga_nothrow_block_stage__ = #stage_name;

#define ARATAGA_NOTHROW_BLOCK_END_STATEMENT_LOG_THEN_IGNORE() \
} \
catch( const std::exception & x ) \
{ \
	const auto line__ = __LINE__; \
	const auto file__ = __FILE__; \
	const auto function__ = __PRETTY_FUNCTION__; \
	try \
	{ \
		if( !arataga_nothrow_block_stage__ ) arataga_nothrow_block_stage__ = "unspecified"; \
		::arataga::logging::direct_mode::err( \
				[arataga_nothrow_block_stage__, &x, &line__, &file__, &function__] \
				( auto & logger, auto level ) { \
					logger.log( level, "{}:{} [{}] unexpected exception at stage '{}' => {}", \
							file__, line__, function__, arataga_nothrow_block_stage__, x.what() ); \
				} ); \
	} \
	catch( ... ) {} \
} \
catch( ... ) \
{ \
	const auto line__ = __LINE__; \
	const auto file__ = __FILE__; \
	const auto function__ = __PRETTY_FUNCTION__; \
	try \
	{ \
		if( !arataga_nothrow_block_stage__ ) arataga_nothrow_block_stage__ = "unspecified"; \
		::arataga::logging::direct_mode::err( \
				[arataga_nothrow_block_stage__, &line__, &file__, &function__] \
				( auto & logger, auto level ) { \
					logger.log( level, "{}:{} [{}] unexpected exception at stage '{}', description not available", \
							file__, line__, function__, arataga_nothrow_block_stage__ ); \
				} ); \
	} \
	catch( ... ) {} \
}

#define ARATAGA_NOTHROW_BLOCK_END_STATEMENT_LOG_THEN_ABORT() \
} \
catch( const std::exception & x ) \
{ \
	const auto line__ = __LINE__; \
	const auto file__ = __FILE__; \
	const auto function__ = __PRETTY_FUNCTION__; \
	try \
	{ \
		if( !arataga_nothrow_block_stage__ ) arataga_nothrow_block_stage__ = "unspecified"; \
		::arataga::logging::direct_mode::critical( \
				[arataga_nothrow_block_stage__, &x, &line__, &file__, &function__] \
				( auto & logger, auto level ) { \
					logger.log( level, "{}:{} [{}] unexpected exception at stage '{}' => {}", \
							file__, line__, function__, arataga_nothrow_block_stage__, x.what() ); \
				} ); \
	} \
	catch( ... ) {} \
	std::abort(); \
} \
catch( ... ) \
{ \
	const auto line__ = __LINE__; \
	const auto file__ = __FILE__; \
	const auto function__ = __PRETTY_FUNCTION__; \
	try \
	{ \
		if( !arataga_nothrow_block_stage__ ) arataga_nothrow_block_stage__ = "unspecified"; \
		::arataga::logging::direct_mode::critical( \
				[arataga_nothrow_block_stage__, &line__, &file__, &function__] \
				( auto & logger, auto level ) { \
					logger.log( level, "{}:{} [{}] unexpected exception at stage '{}', description not available", \
							file__, line__, function__, arataga_nothrow_block_stage__ ); \
				} ); \
	} \
	catch( ... ) {} \
	std::abort(); \
}

#define ARATAGA_NOTHROW_BLOCK_END_STATEMENT_JUST_IGNORE() \
} \
catch( ... ) {}

/*!
 * Finishes block started by ARATAGA_NOTHROW_BLOCK_BEGIN.
 *
 * @a action can be LOG_THEN_IGNORE, LOG_THEN_ABORT or JUST_IGNORE.
 *
 * Usage example:
 * @code
 * ARATAGA_NOTHROW_BLOCK_BEGIN()
 * 	... // Some code inside.
 * ARATAGA_NOTHROW_BLOCK_END(JUST_IGNORE)
 * ...
 * ARATAGA_NOTHROW_BLOCK_BEGIN()
 * 	ARATAGA_NOTHROW_BLOCK_STAGE(first_stage)
 * 	... // Some code
 *
 * 	ARATAGA_NOTHROW_BLOCK_STAGE(second_stage)
 * 	... // Some code
 * ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_IGNORE)
 * @endcode
 */
#define ARATAGA_NOTHROW_BLOCK_END(action) \
	ARATAGA_NOTHROW_BLOCK_END_STATEMENT_##action() \
}


