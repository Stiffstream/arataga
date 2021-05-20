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

[[nodiscard]]
std::chrono::milliseconds
no_delay_marker()
{
	return std::chrono::milliseconds::zero();
}

[[nodiscard]]
bool
is_delay_defined( std::chrono::milliseconds max_value )
{
	return max_value != std::chrono::milliseconds::zero();
}

struct cmd_line_args_t
{
	std::uint16_t m_port_range_left{ 3000u };
	std::uint16_t m_port_range_right{ 8000u };

	unsigned int m_parallel_requests{ 2000u };
	unsigned long m_total_requests{ 10000u };

	asio::ip::address_v4 m_proxy_addr;
	asio::ip::address_v4 m_target_addr;
	std::uint16_t m_target_port{ 8080u };

	std::chrono::milliseconds m_max_connect_delay{ no_delay_marker() };
	std::chrono::milliseconds m_max_send_delay{ no_delay_marker() };
	std::chrono::milliseconds m_max_receive_delay{ no_delay_marker() };
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

	// The common params.

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

	args::ValueFlag< std::uint16_t > max_connect_delay( parser,
			"max-connect-delay",
			"Set max delay for random pause before connect. Milliseconds",
			{ "max-connect-delay" } );
	args::ValueFlag< std::uint16_t > max_send_delay( parser,
			"max-send-delay",
			"Set max delay for random pause before sending the request. "
					"Milliseconds",
			{ "max-send-delay" } );
	args::ValueFlag< std::uint16_t > max_receive_delay( parser,
			"max-receive-delay",
			"Set max delay for random pause before receiving a response. "
					"Milliseconds",
			{ "max-receive-delay" } );

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

	if( max_connect_delay )
	{
		result.m_max_connect_delay = std::chrono::milliseconds{
				static_cast<std::int32_t>( args::get( max_connect_delay ) )
		};
	}
	if( max_send_delay )
	{
		result.m_max_send_delay = std::chrono::milliseconds{
				static_cast<std::int32_t>( args::get( max_send_delay ) )
		};
	}
	if( max_receive_delay )
	{
		result.m_max_receive_delay = std::chrono::milliseconds{
				static_cast<std::int32_t>( args::get( max_receive_delay ) )
		};
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
	std::uniform_int_distribution< std::int32_t > m_connect_delay_generator;
	std::uniform_int_distribution< std::int32_t > m_send_delay_generator;
	std::uniform_int_distribution< std::int32_t > m_receive_delay_generator;

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
		asio::ip::tcp::endpoint target_addr,
		std::chrono::milliseconds connect_delay,
		std::chrono::milliseconds send_delay,
		std::chrono::milliseconds receive_delay );

	void
	start();

private:
	manager_t * m_manager;
	asio::ip::tcp::socket m_connection;
	const asio::ip::tcp::endpoint m_proxy_addr;
	const asio::ip::tcp::endpoint m_target_addr;

	const std::chrono::milliseconds m_connect_delay;
	const std::chrono::milliseconds m_send_delay;
	const std::chrono::milliseconds m_receive_delay;

	void
	run();

	void
	initiate_connect_attempt();

	void
	do_connect_attempt();

	void
	complete( completion_t completion );

	void
	on_connect_result(
		const asio::error_code & ec );

	void
	initiate_send_attempt();

	void
	do_send_attempt();

	void
	on_write_result(
		const asio::error_code & ec,
		std::size_t bytes_transferred );

	void
	initiate_receive_attempt();

	void
	do_receive_attempt();

	void
	on_read_result(
		const asio::error_code & ec,
		std::size_t bytes_transferred );
};

//
// manager_t implementation
//
namespace manager_impl
{

[[nodiscard]]
std::int32_t
delay_generator_right_border( std::chrono::milliseconds max_value ) noexcept
{
	if( is_delay_defined( max_value ) )
		return static_cast<int32_t>(max_value.count());
	else
		return 1;
}

template< typename Random_Generator, typename Distribution >
[[nodiscard]]
std::chrono::milliseconds
generate_delay(
	std::chrono::milliseconds max_delay,
	Random_Generator & generator,
	Distribution & distribution )
{
	if( is_delay_defined( max_delay ) )
		return std::chrono::milliseconds{ distribution( generator ) };
	else
		return no_delay_marker();
}

} /* manager_impl */

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
	,	m_connect_delay_generator{
			0,
			manager_impl::delay_generator_right_border(
					m_config.m_max_connect_delay )
		}
	,	m_send_delay_generator{
			0,
			manager_impl::delay_generator_right_border(
					m_config.m_max_send_delay )
		}
	,	m_receive_delay_generator{
			0,
			manager_impl::delay_generator_right_border(
					m_config.m_max_receive_delay )
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
					m_config.m_target_port },
			manager_impl::generate_delay(
					m_config.m_max_connect_delay,
					m_generator,
					m_connect_delay_generator ),
			manager_impl::generate_delay(
					m_config.m_max_send_delay,
					m_generator,
					m_send_delay_generator ),
			manager_impl::generate_delay(
					m_config.m_max_receive_delay,
					m_generator,
					m_receive_delay_generator )
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
	asio::ip::tcp::endpoint target_addr,
	std::chrono::milliseconds connect_delay,
	std::chrono::milliseconds send_delay,
	std::chrono::milliseconds receive_delay )
	:	m_manager{ manager }
	,	m_connection{ manager->io_context() }
	,	m_proxy_addr{ proxy_addr }
	,	m_target_addr{ target_addr }
	,	m_connect_delay{ connect_delay }
	,	m_send_delay{ send_delay }
	,	m_receive_delay{ receive_delay }
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
	initiate_connect_attempt();
}

void
request_performer_t::initiate_connect_attempt()
{
	if( !is_delay_defined( m_connect_delay ) )
		do_connect_attempt();
	else
	{
		auto timer = std::make_shared< asio::steady_timer >(
				m_connection.get_executor() );
		timer->expires_after( m_connect_delay );
		timer->async_wait(
				[self = shared_from_this(), timer]
				( const auto & ec ) {
					if( !ec )
						self->do_connect_attempt();
					else
						self->complete( completion_t::failure );
				} );
	}
}

void
request_performer_t::do_connect_attempt()
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
		initiate_send_attempt();
	}
}

void
request_performer_t::initiate_send_attempt()
{
	if( !is_delay_defined( m_send_delay ) )
		do_send_attempt();
	else
	{
		auto timer = std::make_shared< asio::steady_timer >(
				m_connection.get_executor() );
		timer->expires_after( m_send_delay );
		timer->async_wait(
				[self = shared_from_this(), timer]
				( const auto & ec ) {
					if( !ec )
						self->do_send_attempt();
					else
						self->complete( completion_t::failure );
				} );
	}
}

void
request_performer_t::do_send_attempt()
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
		initiate_receive_attempt();
	}
}

void
request_performer_t::initiate_receive_attempt()
{
	if( !is_delay_defined( m_receive_delay ) )
		do_receive_attempt();
	else
	{
		auto timer = std::make_shared< asio::steady_timer >(
				m_connection.get_executor() );
		timer->expires_after( m_receive_delay );
		timer->async_wait(
				[self = shared_from_this(), timer]
				( const auto & ec ) {
					if( !ec )
						self->do_receive_attempt();
					else
						self->complete( completion_t::failure );
				} );
	}
}

void
request_performer_t::do_receive_attempt()
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

