#include <arataga/utils/spdlog_log_levels.hpp>
#include <arataga/utils/ensure_successful_syscall.hpp>

#include <arataga/startup_manager/pub.hpp>

#include <arataga/logging/wrap_logging.hpp>

#include <arataga/nothrow_block/macros.hpp>

#include <sys/prctl.h>
#include <signal.h>
#include <unistd.h>

#include <iostream>
#include <stdexcept>
#include <memory>
#include <array>
#include <cerrno>
#include <system_error>
#include <fstream>
#include <vector>
#include <filesystem>
#include <fstream>

#include <args/args.hxx>

#include <optional>

#include <spdlog/logger.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/syslog_sink.h>

#include <fmt/ostream.h>
#include <fmt/chrono.h>

#include <so_5/all.hpp>

namespace {

const char version_string[] =
R"ver(arataga v.0.4.4.3
[--io-threads all]
[socks5 auth+username/password PDU workaround]
[own dns lookup]

(c) 2020-2021 stiffstream (https://stiffstream.com)
)ver";

//
// to_string
//

[[nodiscard]]
std::string
to_string( const spdlog::string_view_t what )
{
	return std::string( what.data(), what.size() );
}

//
// detec_log_level
//

[[nodiscard]]
spdlog::level::level_enum
detec_log_level(const std::string & name)
{
	const auto r = arataga::utils::name_to_spdlog_level_enum( name );

	if( !r )
	{
		throw std::runtime_error( "Unsupported log-level: " + name );
	}

	return *r;
}

// Available values for command-line arguments related to logging to console.
const std::string stdout_log_target = "stdout";
const std::string stderr_log_target = "stderr";

//
// log_params_t
//

//! Logging parameters.
struct log_params_t
{
	void
	set_target( const std::string & target )
	{
		if( stdout_log_target == target ||
			stderr_log_target == target )
		{
			set_console_target( target );
		}
		else if( '@' == target[0] )
		{
			if( target.length() < 2u )
				throw std::runtime_error("invalid log-target name: " +
						target);

			set_syslog_target( target.substr(1u) );
		}
		else
			set_file_target( target );
	}

	std::optional< std::string > m_console_target;
	std::optional< std::string > m_syslog_target;
	std::optional< std::string > m_file_target;

	spdlog::level::level_enum m_log_level{ spdlog::level::trace };
	spdlog::level::level_enum m_log_flush_level{ spdlog::level::err };
	std::size_t m_log_file_size{ 10ull*1024u*1024u };
	std::size_t m_log_file_count{ 3u };

private:

	void
	set_console_target( const std::string & target )
	{
		if( !m_console_target )
		{
			m_console_target = target;
		}
		else
			throw std::runtime_error(
				"console target is present: " + *m_console_target + ", "
				"additional target: " + target );
	}

	void
	set_syslog_target( const std::string & target )
	{
		if( !m_syslog_target )
		{
			m_syslog_target = target;
		}
		else
			throw std::runtime_error(
				"syslog target is present: " + *m_syslog_target + ", "
				"additional target: " + target );
	}

	void
	set_file_target( const std::string & target )
	{
		if( !m_file_target )
		{
			m_file_target = target;
		}
		else
			throw std::runtime_error(
				"file target is present: " + *m_file_target + ", "
				"additional target: " + target );
	}
};

std::ostream &
operator<<( std::ostream & o, const log_params_t & params )
{
	if(params.m_console_target)
		fmt::print( o, "(console_target {}) ", *(params.m_console_target) );

	if(params.m_syslog_target)
		fmt::print( o, "(syslog_target {}) ", *(params.m_syslog_target) );

	if(params.m_file_target)
		fmt::print( o, "(file_target {}) ", *(params.m_file_target) );

	fmt::print( o, "(log_level {}) ",
		spdlog::level::to_string_view(params.m_log_level) );
	fmt::print( o, "(log_flush_level {}) ",
		spdlog::level::to_string_view(params.m_log_flush_level) );

	fmt::print( o, "(log_file_size {}) ", params.m_log_file_size );
	fmt::print( o, "(log_file_count {}) ", params.m_log_file_count );

	return o;
}

//
// cmd_line_args_t
//

//! Command-line arguments.
struct cmd_line_args_t
{
	bool m_is_no_daemonize{ false };

	std::optional<gid_t> m_setgid;
	std::optional<uid_t> m_setuid;

	log_params_t m_log_params;

	asio::ip::address m_admin_http_ip;
	std::uint16_t m_admin_http_port;
	std::string m_admin_token;

	std::string m_local_config_path;

	//! Should combined_locks from SObjectizer be used?
	/*!
	 * Combined_locks provide low-latency (by using spin-locks), but
	 * consume CPU. Because of that simple_locks are used by default.
	 */
	bool m_use_so5_combined_locks{ false };

	//! Max time for the completion of one initialization stage.
	std::chrono::seconds m_max_stage_startup_time{ 5 };

	//! Count of io_threads to be created.
	/*!
	 * If that value is missed then the count of io_threads has to
	 * be detected automatically.
	 */
	arataga::io_threads_count_t m_io_threads_count{
			arataga::io_threads_count::default_t{} };
};

std::ostream &
operator<<( std::ostream & o, const cmd_line_args_t & args )
{
	if( args.m_is_no_daemonize )
		fmt::print( o, "(no_daemonize) " );

	if( args.m_setgid )
		fmt::print( o, "(setgid {}) ", *(args.m_setgid) );

	if( args.m_setuid )
		fmt::print( o, "(setuid {}) ", *(args.m_setuid) );

	fmt::print( o, "(log_params {}) ", args.m_log_params );

	fmt::print( o, "(admin_http_ip {}) ", args.m_admin_http_ip.to_string() );
	fmt::print( o, "(admin_http_port {}) ", args.m_admin_http_port );
	fmt::print( o, "(admin_token {}) ", args.m_admin_token );

	fmt::print( o, "(local_config_path {}) ", args.m_local_config_path );

	if( args.m_use_so5_combined_locks )
		fmt::print( o, "(use_so5_combined_locks) " );

	fmt::print( o, "(max_stage_startup_time {}) ",
			args.m_max_stage_startup_time );

	fmt::print( o, "(io_threads {}) ", args.m_io_threads_count );

	return o;
}

//
// finish_app_ex_t
//

//! An exception for errors related to command-line args parsing.
/*!
 * If such an exception is throw then the application has to be finished.
 */
class finish_app_ex_t : public std::runtime_error {

	int m_exit_code;

public:
	finish_app_ex_t(
		const char * what_arg,
		int exit_code )
	:	std::runtime_error{ what_arg }
	,	m_exit_code{ exit_code }
	{
	}

	int
	exit_code() const noexcept { return m_exit_code; }
};

//
// parse_cmd_line
//

/*!
 * Returns values of command-line args or throws finish_app_ex_t
 * in the case of an error.
 */
[[nodiscard]]
cmd_line_args_t
parse_cmd_line( int argc, char ** argv )
{
	cmd_line_args_t result;

	args::ArgumentParser parser( "arataga", "\n" );

	// Common parameters.

	args::HelpFlag help( parser, "help", "Display this help text",
			{ 'h', "help" } );

	args::Flag version(parser, "version", "Show verion number and "
			"description", { 'v', "version" } );

	// Parameters related to Linux.

	args::Flag no_daemonize( parser, "no-daemonize",
			"Ignore 'daemon' command in configuration",
			{ "no-daemonize" } );

	args::ValueFlag< uint32_t > setuid( parser,
			"uid", "Set user identifier for the process"
			" (default: setuid() isn't called )",
			{ "setuid" } );

	args::ValueFlag< uint32_t > setgid( parser,
			"gid", "Set group identifier for the process"
			" (default: setgid() isn't called )",
			{ "setgid" } );

	// Parameters for logging.

	args::ValueFlagList< std::string > log_target( parser,
		"name", "Set log destination. "
		"Value 'stdout' means the standard output stream. "
		"Value 'stderr' means the standard error stream. "
		"Value '@something' means syslog as 'something'. "
		"Other values mean a file name. "
		" (default: " + stdout_log_target + ")",
		{ "log-target" } );

	args::ValueFlag< std::string > log_level( parser,
			"level", "Set logging level. Value 'off' turns logging off "
			" (default: " + to_string(
				spdlog::level::to_string_view(
					result.m_log_params.m_log_level) )+ ")",
			{ 'l', "log-level" } );

	args::ValueFlag< std::string > log_flush_level( parser,
			"level", "Set flush level. Value 'off' turns flushing off "
			" (default: " +
			to_string(
				spdlog::level::to_string_view(
					result.m_log_params.m_log_flush_level) ) + ")",
			{ 'f', "log-flush-level" } );

	args::ValueFlag< unsigned int > log_file_size( parser,
			"bytes", "Set maximum size of log file"
			" (default: " + std::to_string(
				result.m_log_params.m_log_file_size ) + ")",
			{ "log-file-size" } );

	args::ValueFlag< unsigned int > log_file_count( parser,
			"non-zero-value", "Set maximum count of log files in rotation. "
			"This value should be at least 2 "
			" (default: " + std::to_string(
				result.m_log_params.m_log_file_count ) + ")",
			{ "log-file-count" } );

	// Parameters for HTTP-server.

	args::ValueFlag<std::string> admin_http_ip( parser,
			"char-seq", "Set admin http endpoint ip-address."
			" [required parameter]",
			{"admin-http-ip"});

	args::ValueFlag<unsigned short> admin_http_port( parser,
			"ushort", "Set http port. [required parameter]",
			{"admin-http-port"});

	args::ValueFlag<std::string> admin_token( parser,
			"char-seq", "Set admin token passed in header."
			" [required parameter]",
			{"admin-token"});

	// A path for local copy of config.

	args::ValueFlag<std::string> local_config_path( parser,
			"path", "Set path to local configuration."
			" [required parameter]",
			{"local-config-path"});

	// Parameters for SObjectizer.

	args::Flag use_so5_combined_locks( parser, "so5-combined-locks",
			"Use SObjectizer's combined_locks (low-latency, high CPU usage)."
			" (default: simple_locks are used instead of combined_locks)",
			{ "so5-combined-locks" } );

	args::ValueFlag<unsigned int> max_stage_startup_time( parser,
			"uint",
			fmt::format( "Max time for one startup stage in seconds "
					"(default: {})",
					result.m_max_stage_startup_time.count() ),
			{"max-stage-startup-time"});

	args::ValueFlag<std::string> io_threads_count( parser,
			"uint|default|all",
			"Count of IO-threads to be created "
					"(default: detected automatically as nCPU-2)",
			{"io-threads"});

	try
	{
		parser.ParseCLI( argc, argv );
	}
	catch( const args::Completion & e )
	{
		std::cout << e.what();
		throw finish_app_ex_t("bash-completion", 0);
	}
	catch( const args::Help & /*e*/ )
	{
		std::cout << parser;
		throw finish_app_ex_t( "cmd-line-help", 1 );
	}
	catch( const args::ParseError & e )
	{
		std::cerr << e.what() << std::endl;
		throw finish_app_ex_t( "cmd-line-parse-error", 2 );
	}

	if( version )
	{
		std::cout << version_string << std::endl;
		throw finish_app_ex_t( "show-version-only", 0 );
	}

	if( no_daemonize )
		result.m_is_no_daemonize = true;
	if( setuid )
		result.m_setuid = args::get( setuid );
	if( setgid )
		result.m_setgid = args::get( setgid );

	if( log_target )
	{
		for ( const auto & nm: args::get( log_target ) )
		{
			result.m_log_params.set_target(nm);
		}
	}
	if( log_level )
		result.m_log_params.m_log_level = detec_log_level( args::get( log_level ) );
	if( log_flush_level )
		result.m_log_params.m_log_flush_level = detec_log_level(
			args::get( log_flush_level ) );
	if( log_file_size )
	{
		result.m_log_params.m_log_file_size = args::get( log_file_size );
		if(0u == result.m_log_params.m_log_file_size)
			throw std::runtime_error("zero can be used as log-file-size");
	}
	if( log_file_count )
	{
		result.m_log_params.m_log_file_count = args::get( log_file_count );
		if( 2u > result.m_log_params.m_log_file_count )
			throw std::runtime_error( "log-file-count should be at least 2" );
	}

	if( admin_http_ip)
	{
		asio::error_code ec;
		result.m_admin_http_ip = asio::ip::make_address(
			args::get( admin_http_ip ).c_str(), ec );

		if(ec)
			throw std::runtime_error("invalid value of --admin-http-ip");
	}
	else
		throw std::runtime_error( "param --admin-http-ip is absent" );
	if( admin_http_port )
		result.m_admin_http_port = args::get( admin_http_port );
	else
		throw std::runtime_error( "param --admin-http-port is absent" );
	if( admin_token )
		result.m_admin_token = args::get( admin_token );
	else
		throw std::runtime_error( "param --admin-token is absent" );

	if( local_config_path )
		result.m_local_config_path = args::get( local_config_path );
	else
		throw std::runtime_error( "param --local-config-path is absent" );

	if( use_so5_combined_locks )
		result.m_use_so5_combined_locks = true;

	if( max_stage_startup_time )
	{
		if( const auto v = args::get( max_stage_startup_time );
				0u != v )
		{
			result.m_max_stage_startup_time =
					std::chrono::seconds{ static_cast<int>(v) };
		}
		else
			throw std::runtime_error( "param --max-stage-startup-time can't "
					"be zero" );
	}

	if( io_threads_count )
	{
		const auto v = args::get( io_threads_count );
		if( "default" == v )
			result.m_io_threads_count = arataga::io_threads_count::default_t{};
		else if( "all" == v )
			result.m_io_threads_count = arataga::io_threads_count::all_cores_t{};
		else
		{
			const auto n = std::stoul( v );
			if( 0u == n )
				throw std::runtime_error( "param --io-threads can't be zero" );
			result.m_io_threads_count = arataga::io_threads_count::exact_t{n};
		}
	}

	return result;
}

const std::array<int, 6> SIGNALS_TO_HANDLE{
	SIGINT, SIGHUP, SIGQUIT, SIGTERM, SIGPIPE, SIGCHLD
};

template<typename Container>
void
fill_sigset(sigset_t & what, const Container & signals)
{
	sigemptyset(&what);
	for(auto s : signals)
	{
		::arataga::utils::ensure_successful_syscall(
				sigaddset(&what, s),
				"fill_sigset.sigaddset()");
	}
}

void
block_signals_for_current_process()
{
	sigset_t sigset;
	fill_sigset(sigset, SIGNALS_TO_HANDLE);

	::arataga::utils::ensure_successful_syscall(
			sigprocmask(SIG_BLOCK, &sigset, nullptr),
			"block_signals_for_current_process.sigprocmask()");
}

void
try_to_create_test_file( const std::filesystem::path & path )
{
	std::string tmp_file_name = "tmp";
	std::string test_data = "check";

	{
		std::ofstream tmp( path / tmp_file_name );
		if(!tmp.is_open() )
		{
			throw std::runtime_error("tmp file is not created in config path.");
		}

		tmp << test_data;
	}
	{
		std::ifstream tmp( path / tmp_file_name );

		if(!tmp.is_open() )
		{
			throw std::runtime_error("tmp file is not opened in config path.");
		}

		std::string to_check;
		std::getline(tmp, to_check);

		if(to_check != test_data)
			throw std::runtime_error("something wrong with writing or reading from file.");
	}

	std::filesystem::remove(path / tmp_file_name);
}

//! Helper function for checking the correctness of a particular path.
/*!
 * Checks for existence of the path. Checks a possibility to
 * create a file inside the path, writing to that file and reading from that
 * file.
 *
 * @throws std::runtime_error In the case if check fails.
 */
void
ensure_local_config_path_is_present( const std::string & local_lonfig_path )
{
	std::filesystem::path path = local_lonfig_path;

	if( !std::filesystem::exists(path) )
		throw std::runtime_error("local config path is not exists.");

	if( !std::filesystem::is_directory(path) )
		throw std::runtime_error("local config path is not a directory.");

	try_to_create_test_file(path);
}

void
run_loop()
{
	sigset_t sigset;
	sigemptyset(&sigset);
	for(auto s : SIGNALS_TO_HANDLE)
		::arataga::utils::ensure_successful_syscall(
				sigaddset(&sigset, s),
				"run_loop.sigaddset()");

	for(;;) {
		int signal;
		int rc = sigwait(&sigset, &signal);

		if(0 != rc)
			throw std::runtime_error("sigwait failed -> " +
					std::system_category().message(errno));

		switch(signal) {
			case SIGINT: std::cout << "*** SIGINT..." << std::endl;
				return;

			case SIGHUP: std::cout << "*** SIGHUP..." << std::endl;
				return;

			case SIGQUIT: std::cout << "*** SIGQUIT..." << std::endl;
				return;

			case SIGTERM: std::cout << "*** SIGTERM..." << std::endl;
				return;

			case SIGPIPE: break;

			case SIGCHLD: std::cout << "*** SIGCHLD..." << std::endl;
				return;
		}
	}
}

//
// prepare_process
//

void
prepare_process(
	const cmd_line_args_t & params)
{
	// Daemonize only if there is 'daemon' command in the config
	// and this command is not overriden by command-line argument.
	if(!params.m_is_no_daemonize)
	{
		::arataga::utils::ensure_successful_syscall(
				// set nochdir to 1 because original proxy didn't change
				// working directory to '/' in its 'daemonize()' implementation.
				daemon(1, 0),
				"prepare_process.daemon()");
	}

	if(params.m_setgid)
	{
		::arataga::utils::ensure_successful_syscall(
			setgid(*params.m_setgid),
			"prepare_process.setgit()" );
	}

	if(params.m_setuid)
	{
		::arataga::utils::ensure_successful_syscall(
			setuid(*params.m_setuid),
			"prepare_process.setuid()" );
	}

	block_signals_for_current_process();
}

//
// sink_list_t
//

using sink_list_t = std::vector<spdlog::sink_ptr>;

[[nodiscard]]
sink_list_t
make_sinks( const log_params_t & log_params )
{
	sink_list_t result;

	if( log_params.m_console_target )
	{
		spdlog::sink_ptr console_sink;

		if( stdout_log_target == *(log_params.m_console_target) )
			console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
		else //if( stderr_log_target == *(log_params.m_console_target) )
			console_sink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();

		result.push_back(console_sink);
	}

	if( log_params.m_syslog_target )
	{
		int syslog_option = 0;
		int syslog_facility = 1; // user-level messages
		bool enable_formatting = true;

		result.push_back(
			std::make_shared<spdlog::sinks::syslog_sink_mt>(
				*(log_params.m_syslog_target),
				syslog_option, syslog_facility,
				enable_formatting) );
	}

	if( log_params.m_file_target )
	{
		result.push_back(
			std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
				*(log_params.m_file_target),
				log_params.m_log_file_size,
				log_params.m_log_file_count) );
	}

	if( result.empty() )
	{
		result.push_back(
			std::make_shared<spdlog::sinks::stdout_color_sink_mt>() );
	}

	return result;
}

[[nodiscard]]
std::shared_ptr<spdlog::logger>
make_logger(
	std::string logger_name,
	const sink_list_t & sinks,
	const log_params_t & log_params )
{
	auto logger = std::make_shared< spdlog::logger >(
		std::move(logger_name), sinks.begin(), sinks.end() );

	logger->set_level( log_params.m_log_level );
	logger->flush_on( log_params.m_log_flush_level );

	return logger;
}

// Helper function for tuning of SObjectizer parameters.
[[nodiscard]]
so_5::environment_params_t
make_sobjectizer_params(
	const cmd_line_args_t & cmd_line_args )
{
	// Special logger that redirects all error messages to
	// the application logger.
	class so5_error_logger_t : public so_5::error_logger_t
	{
	public:
		so5_error_logger_t() = default;

		void
		log(
			const char * file_name,
			unsigned int line,
			const std::string & message ) override
		{
			ARATAGA_NOTHROW_BLOCK_BEGIN()
				ARATAGA_NOTHROW_BLOCK_STAGE(log_error_msg)

				::arataga::logging::wrap_logging(
						::arataga::direct_logging_mode,
						spdlog::level::err,
						[&]( auto & logger, auto level )
						{
							logger.log(
									level,
									"an error detected by SObjectizer: {} (at {}:{})",
									message, file_name, line );
						} );
			ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_IGNORE)
		}
	};

	// Special logger that logs exceptions thrown from event-handlers.
	class so5_event_exception_logger_t : public so_5::event_exception_logger_t
	{
	public:
		so5_event_exception_logger_t() = default;

		void
		log_exception(
			const std::exception & event_exception,
			const so_5::coop_handle_t & coop ) noexcept override
		{
			// This method can't throw. So catch all exceptions.
			ARATAGA_NOTHROW_BLOCK_BEGIN()
				ARATAGA_NOTHROW_BLOCK_STAGE(log_exception)

				::arataga::logging::wrap_logging(
						::arataga::direct_logging_mode,
						spdlog::level::err,
						[&]( auto & logger, auto level )
						{
							logger.log(
									level,
									"an exception from SObjectizer's agent event: \"{}\", "
									"agent's coop ID: {}",
									event_exception.what(),
									coop.id() );
						} );
			ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_IGNORE)
		}
	};

	so_5::environment_params_t params;

	params.error_logger( std::make_shared< so5_error_logger_t >() );
	params.event_exception_logger(
			std::make_unique< so5_event_exception_logger_t >() );

	if( cmd_line_args.m_use_so5_combined_locks )
		params.queue_locks_defaults_manager(
				so_5::make_defaults_manager_for_combined_locks() );
	else
		params.queue_locks_defaults_manager(
				so_5::make_defaults_manager_for_simple_locks() );

	return params;
}

void
make_startup_manager(
	so_5::environment_t & env,
	const cmd_line_args_t & cmd_line_args )
{
	using namespace arataga::startup_manager;

	introduce_startup_manager(
			env,
			params_t{
					cmd_line_args.m_local_config_path,
					cmd_line_args.m_max_stage_startup_time,
					cmd_line_args.m_io_threads_count,
					cmd_line_args.m_admin_http_ip,
					cmd_line_args.m_admin_http_port,
					cmd_line_args.m_admin_token
			} );
}

} /* anonimous namespace */

int
main(int argc, char ** argv)
{

	try
	{
		const auto cmd_line_args = parse_cmd_line( argc, argv );

		auto sinks =  make_sinks( cmd_line_args.m_log_params );
		arataga::logging::logger_holder_t log_holder{
				make_logger( "arataga", sinks, cmd_line_args.m_log_params )
		};

		prepare_process( cmd_line_args );
		ensure_local_config_path_is_present( cmd_line_args.m_local_config_path );

		std::cout << cmd_line_args << std::endl;

		so_5::wrapped_env_t sobj{
			[&cmd_line_args]( so_5::environment_t & env ) {
				make_startup_manager(
						env,
						cmd_line_args );
			},
			[&cmd_line_args]( so_5::environment_params_t & params ) {
				params = make_sobjectizer_params( cmd_line_args );
			}
		};

		run_loop();
	}
	catch(const finish_app_ex_t & need_finish) {
		return need_finish.exit_code();
	}
	catch(const std::exception & ex)
	{
		std::cerr << "*** Exception caught: " << ex.what() << std::endl;
		return 2;
	}
	catch(...)
	{
		std::cerr << "*** Unknown exception caught! ***" << std::endl;
	}

	return 0;
}

