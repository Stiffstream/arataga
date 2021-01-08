#include <args/args.hxx>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <asio.hpp>

#include <cstdint>
#include <optional>
#include <iostream>
#include <random>
#include <memory>

namespace mass_load
{

struct cmd_line_args_t
{
	std::uint16_t m_port_range_left{ 3000u };
	std::uint16_t m_port_range_right{ 8000u };

	unsigned int m_parallel_requests{ 2000u };
	unsigned long m_total_requests{ 10000u };

	asio::ip::address_v4 m_proxy_addr;
	asio::ip::address_v4 m_target_addr;
	std::uint16_t m_target_port{ 8080u };
};

[[nodiscard]]
std::optional<asio::ip::address_v4>
try_extract_address_v4( const std::string & from )
{
	asio::error_code ec;
	asio::ip::address_v4 r = asio::ip::make_address_v4( from, ec );
	if( ec )
		return std::nullopt;
	return r;
}

[[nodiscard]]
std::optional<cmd_line_args_t>
parse_cmd_line( int argc, char ** argv )
{
	cmd_line_args_t result;

	args::ArgumentParser parser( "mass_load", "\n" );

	// Общие параметры.

	args::HelpFlag help( parser, "help", "Display this help text",
			{ 'h', "help" } );

	args::ValueFlag< std::uint16_t > port_range_left( parser,
			"port",
			fmt::format( "Set the left border of ports range (default: {})",
					result.m_port_range_left ),
			{ 'L', "port-range-left" } );
	args::ValueFlag< std::uint16_t > port_range_right( parser,
			"port",
			fmt::format( "Set the right border of ports range (default: {})",
					result.m_port_range_right ),
			{ 'R', "port-range-right" } );

	args::ValueFlag< unsigned int > parallel_requests( parser,
			"uint",
			fmt::format( "Set the amount of parallel requests (default: {})",
					result.m_parallel_requests ),
			{ 'P', "parallel-requests" } );

	args::ValueFlag< unsigned long > total_requests( parser,
			"uint",
			fmt::format( "Set the total amount of requests (default: {})",
					result.m_total_requests ),
			{ 'T', "total-requests" } );

	args::ValueFlag< std::string > proxy_addr( parser,
			"IPv4-addr",
			"Set IPv4 address of the proxy",
			{ 'p', "proxy-addr" } );

	args::ValueFlag< std::string > target_addr( parser,
			"IPv4-addr",
			"Set IPv4 address of the target",
			{ 't', "target-addr" } );
	args::ValueFlag< std::uint16_t > target_port( parser,
			"port",
			fmt::format( "Set the target port (default: {})",
					result.m_target_port ),
			{ "target-port" } );

	try
	{
		parser.ParseCLI( argc, argv );
	}
	catch( const args::Completion & e )
	{
		std::cout << e.what();
		return std::nullopt;
	}
	catch( const args::Help & e )
	{
		std::cout << parser;
		return std::nullopt;
	}
	catch( const args::ParseError & e )
	{
		std::cerr << e.what() << std::endl;
		return std::nullopt;
	}

	if( port_range_left )
		result.m_port_range_left = args::get( port_range_left );
	if( port_range_right )
		result.m_port_range_right = args::get( port_range_right );

	if( result.m_port_range_right <= result.m_port_range_left )
	{
		fmt::print( std::cerr, "port-range-right ({}) should be greater than "
				"port-range-left ({})\n",
				result.m_port_range_right,
				result.m_port_range_left );
		return std::nullopt;
	}

	if( parallel_requests )
	{
		result.m_parallel_requests = args::get( parallel_requests );
		if( !result.m_parallel_requests )
		{
			fmt::print( std::cerr, "parallel-requests can't be 0\n" );
			return std::nullopt;
		}
	}

	if( total_requests )
	{
		result.m_total_requests = args::get( total_requests );
		if( !result.m_total_requests )
		{
			fmt::print( std::cerr, "total-requests can't be 0\n" );
			return std::nullopt;
		}
	}

	if( proxy_addr )
	{
		const auto & addr_str = args::get( proxy_addr );
		const auto addr = try_extract_address_v4( addr_str );
		if( !addr )
		{
			fmt::print( std::cerr, "invalid proxy-addr value: {}\n", addr_str );
			return std::nullopt;
		}

		result.m_proxy_addr = *addr;
	}
	else
	{
		fmt::print( std::cerr, "proxy-addr must be specified\n" );
		return std::nullopt;
	}

	if( target_addr )
	{
		const auto & addr_str = args::get( target_addr );
		const auto addr = try_extract_address_v4( addr_str );
		if( !addr )
		{
			fmt::print( std::cerr, "invalid target-addr value: {}\n", addr_str );
			return std::nullopt;
		}

		result.m_target_addr = *addr;
	}
	else
	{
		fmt::print( std::cerr, "target-addr must be specified\n" );
		return std::nullopt;
	}

	return result;
}

enum class completion_t { normal, failure };

//
// manager_t declaration
//
class manager_t
{
public:
	manager_t(
		asio::io_context & io_ctx,
		cmd_line_args_t config );

	[[nodiscard]]
	asio::io_context &
	io_context() const noexcept;

	void
	start();

	void
	worker_completed( completion_t completion );

	void
	show_results();

private:
	asio::io_context & m_io_ctx;

	const cmd_line_args_t m_config;

	std::mt19937 m_generator;
	std::uniform_int_distribution< std::uint16_t > m_ports_generator;

	unsigned int m_active_requests{};
	unsigned long m_initiated_requests{};

	unsigned long m_completed_normally{};
	unsigned long m_completed_with_failures{};

	void
	run();

	void
	launch_new_request();
};

//
// request_performer_t declaration
//
class request_performer_t;

using request_performer_shptr_t = std::shared_ptr< request_performer_t >;

class request_performer_t
	:	public std::enable_shared_from_this< request_performer_t >
{
public:
	request_performer_t(
		manager_t * manager,
		asio::ip::tcp::endpoint proxy_addr,
		asio::ip::tcp::endpoint target_addr );

	void
	start();

private:
	manager_t * m_manager;
	asio::ip::tcp::socket m_connection;
	const asio::ip::tcp::endpoint m_proxy_addr;
	const asio::ip::tcp::endpoint m_target_addr;

	void
	run();

	void
	complete( completion_t completion );

	void
	on_connect_result(
		const asio::error_code & ec );

	void
	on_write_result(
		const asio::error_code & ec,
		std::size_t bytes_transferred );

	void
	on_read_result(
		const asio::error_code & ec,
		std::size_t bytes_transferred );
};

//
// manager_t implementation
//
manager_t::manager_t(
	asio::io_context & io_ctx,
	cmd_line_args_t config )
	:	m_io_ctx{ io_ctx }
	,	m_config{ std::move(config) }
	,	m_generator{ []{ std::random_device rd; return rd(); }() }
	,	m_ports_generator{
			m_config.m_port_range_left,
			m_config.m_port_range_right
		}
{}

[[nodiscard]]
asio::io_context &
manager_t::io_context() const noexcept
{
	return m_io_ctx;
}

void
manager_t::start()
{
	asio::post( m_io_ctx, [this] { this->run(); } );
}

void
manager_t::worker_completed( completion_t completion )
{
	--m_active_requests;

	switch( completion )
	{
	case completion_t::normal: ++m_completed_normally; break;

	case completion_t::failure: ++m_completed_with_failures; break;
	}
	
	if( m_initiated_requests < m_config.m_total_requests &&
			m_active_requests < m_config.m_parallel_requests )
		launch_new_request();
}

void
manager_t::show_results()
{
	fmt::print( std::cout,
			"Total requests: {},\n"
			"  normal completion: {},\n"
			"  failed completion: {}\n",
			m_initiated_requests,
			m_completed_normally,
			m_completed_with_failures );
}

void
manager_t::run()
{
	for( unsigned int i{};
		i != m_config.m_parallel_requests &&
		m_initiated_requests < m_config.m_total_requests; ++i )
	{
		launch_new_request();
	}
}

void
manager_t::launch_new_request()
{
	const auto port = m_ports_generator( m_generator );

	auto new_worker = std::make_shared< request_performer_t >(
			this,
			asio::ip::tcp::endpoint{ m_config.m_proxy_addr, port },
			asio::ip::tcp::endpoint{
					m_config.m_target_addr,
					m_config.m_target_port }
		);
	new_worker->start();

	++m_active_requests;
	++m_initiated_requests;
}

//
// request_performer_t implementation
//
request_performer_t::request_performer_t(
	manager_t * manager,
	asio::ip::tcp::endpoint proxy_addr,
	asio::ip::tcp::endpoint target_addr )
	:	m_manager{ manager }
	,	m_connection{ manager->io_context() }
	,	m_proxy_addr{ proxy_addr }
	,	m_target_addr{ target_addr }
{
}

void
request_performer_t::start()
{
	asio::post( m_connection.get_executor(), [self = shared_from_this()] {
			self->run();
		} );
}

void
request_performer_t::run()
{
	try
	{
		m_connection.async_connect(
				m_proxy_addr,
				[self = shared_from_this()]( const asio::error_code & ec )
				{
					self->on_connect_result( ec );
				} );
	}
	catch( const std::exception & x )
	{
		fmt::print( std::cerr, "exception in request_performer_t::run: {}\n",
				x.what() );
		complete( completion_t::failure );
	}
}

void
request_performer_t::complete( completion_t completion )
{
	asio::post( m_connection.get_executor(),
		[m = m_manager, completion] {
			m->worker_completed( completion );
		} );
}

void
request_performer_t::on_connect_result(
	const asio::error_code & ec )
{
	if( ec )
	{
		fmt::print( std::cerr, "connection failed, proxy={}, error={}\n",
				m_proxy_addr,
				ec.message() );
		complete( completion_t::failure );
	}
	else
	{
		try
		{
			auto request = std::make_shared< std::string >();
			fmt::format_to( std::back_inserter(*request),
					"GET http://{}/?first-param=first-value&"
						"second-param=second-value&last-param=last-value HTTP/1.1\r\n"
					"Host: {}\r\n"
					"Connection: close\r\n"
					"Content-Type: text/plain\r\n"
					"Accept: text/plain\r\n"
					"Content-Length: 0\r\n"
					"\r\n",
					m_target_addr,
					m_target_addr );

			asio::async_write(
					m_connection,
					asio::buffer( *request ),
					[self = shared_from_this(), req = request](
						const asio::error_code & ec,
						std::size_t bytes_transferred )
					{
						self->on_write_result( ec, bytes_transferred );
					} );
		}
		catch( const std::exception & x )
		{
			fmt::print( std::cerr,
					"exception in request_performer_t::on_connect_result: {}\n",
					x.what() );
			complete( completion_t::failure );
		}
	}
}

void
request_performer_t::on_write_result(
	const asio::error_code & ec,
	std::size_t /*bytes_transferred*/ )
{
	if( ec )
	{
		fmt::print( std::cerr, "request writing failed, proxy={}, error={}\n",
				m_proxy_addr,
				ec.message() );
		complete( completion_t::failure );
	}
	else
	{
		try
		{
			auto response = std::make_shared< std::string >();
			asio::async_read_until(
					m_connection,
					asio::dynamic_buffer( *response ),
					"'last-param' => 'last-value'",
					[self = shared_from_this(), resp = response](
						const asio::error_code & ec,
						std::size_t bytes_transferred )
					{
						self->on_read_result( ec, bytes_transferred );
					} );
		}
		catch( const std::exception & x )
		{
			fmt::print( std::cerr,
					"exception in request_performer_t::on_read_result: {}\n",
					x.what() );
			complete( completion_t::failure );
		}
	}
}

void
request_performer_t::on_read_result(
	const asio::error_code & ec,
	std::size_t bytes_transferred )
{
	if( ec )
	{
		fmt::print( std::cerr, "response reading error, proxy={}, error={}\n"
				"  bytes_transferred: {}\n",
				m_proxy_addr,
				ec.message(),
				bytes_transferred );

		complete( completion_t::failure );
	}
	else
		complete( completion_t::normal );
}

} /* namespace mass_load */

int main( int argc, char ** argv )
{
	using namespace mass_load;

	const auto cmd_line_params = parse_cmd_line( argc, argv );
	if( !cmd_line_params )
		return 1;

	asio::io_context io_ctx;
	manager_t manager{ io_ctx, cmd_line_params.value() };

	manager.start();

	io_ctx.run();

	manager.show_results();

	return 0;
}

