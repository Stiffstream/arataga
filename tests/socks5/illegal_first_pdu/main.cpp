#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN 
#include <doctest/doctest.h>

#include <tests/get_proxy_endpoint_from_envvar.hpp>

#include <tests/connection_handler_simulator/pub.hpp>

#include <asio.hpp>

#include <thread>

using namespace std::string_view_literals;
using namespace std::chrono_literals;

namespace chs = connection_handler_simulator;

TEST_CASE("no first PDU") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	chs::simulator_t simulator{
			proxy_endpoint,
			chs::handler_config_values_t{}
	};

	asio::io_context ctx;

	asio::ip::tcp::socket connection{ ctx };
	REQUIRE_NOTHROW( connection.connect( proxy_endpoint ) );

	std::array< std::uint8_t, 1 > data{ 0x5u };

	std::cout << "Do nothing for 1 second..." << std::endl;
	std::this_thread::sleep_for( 1s );

	// The connection has to be closed on the other side.
	asio::error_code ec;
	REQUIRE_NOTHROW( connection.read_some( asio::buffer(data), ec ) );
	REQUIRE( asio::error::eof == ec );

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("only one byte in PDU") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	chs::simulator_t simulator{
			proxy_endpoint,
			chs::handler_config_values_t{}
	};

	asio::io_context ctx;

	asio::ip::tcp::socket connection{ ctx };
	REQUIRE_NOTHROW( connection.connect( proxy_endpoint ) );

	std::array< std::uint8_t, 1 > data{ 0x5u };

	std::size_t written;
	REQUIRE_NOTHROW( written = connection.write_some( asio::buffer(data) ) );
	REQUIRE( 1u == written );

	// The connection has to be closed on the other side.
	asio::error_code ec;
	REQUIRE_NOTHROW( connection.read_some( asio::buffer(data), ec ) );
	REQUIRE( asio::error::eof == ec );

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("first PDU with a garbage") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	chs::simulator_t simulator{
			proxy_endpoint,
			chs::handler_config_values_t{}
	};

	asio::io_context ctx;

	asio::ip::tcp::socket connection{ ctx };
	REQUIRE_NOTHROW( connection.connect( proxy_endpoint ) );

	std::array< std::uint8_t, 300u > data;
	data[ 0 ] = 0x5u;
	data[ 1 ] = 0x1u; // methods_count
	data[ 2 ] = 0x0u; // no authentification.

	std::size_t written;
	REQUIRE_NOTHROW( written = connection.write_some( asio::buffer(data) ) );
	REQUIRE( data.size() == written );

	// Since v.0.5.0 the size of first PDU isn't checked.
	// So we have to read auth reply PDU.
	asio::error_code ec;
	std::size_t bytes_read{};
	REQUIRE_NOTHROW( bytes_read = connection.read_some( asio::buffer(data) ) );
	REQUIRE( 2u == bytes_read );
	REQUIRE( 0x5u == data[ 0 ] );
	REQUIRE( 0x0u == data[ 1 ] );

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("no appropriate auth method") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	chs::simulator_t simulator{
			proxy_endpoint,
			chs::handler_config_values_t{}
	};

	asio::io_context ctx;

	asio::ip::tcp::socket connection{ ctx };
	REQUIRE_NOTHROW( connection.connect( proxy_endpoint ) );

	std::array< std::uint8_t, 4 > data;
	data[ 0 ] = 0x5u;
	data[ 1 ] = 0x2u; // methods_count
	data[ 2 ] = 0x1u; // GSSAPI
	data[ 3 ] = 0x3u; // Some from reserved.

	std::size_t written;
	REQUIRE_NOTHROW( written = connection.write_some( asio::buffer(data) ) );
	REQUIRE( data.size() == written );

	// 2 bytes in the response are expected.
	std::array< std::uint8_t, 20 > response;
	std::size_t bytes_read;
	REQUIRE_NOTHROW( bytes_read = connection.read_some( asio::buffer(response) ) );

	REQUIRE( 2u == bytes_read );
	REQUIRE( 0x5u == response[ 0 ] );
	REQUIRE( 0xffu == response[ 1 ] );

	// The connection should closed on remote side after that.
	asio::error_code ec;
	REQUIRE_NOTHROW( connection.read_some( asio::buffer(data), ec ) );
	REQUIRE( asio::error::eof == ec );

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

