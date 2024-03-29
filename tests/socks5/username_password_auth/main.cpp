#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN 
#include <doctest/doctest.h>

#include <tests/connection_handler_simulator/pub.hpp>

#include <asio.hpp>

#include <thread>

using namespace std::string_view_literals;
using namespace std::chrono_literals;

namespace chs = connection_handler_simulator;

TEST_CASE("no auth PDU") {
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

	{
		std::array< std::uint8_t, 3 > first_pdu{ 0x5u, 0x1u, 0x2u };
		std::size_t written;
		REQUIRE_NOTHROW( written = connection.write_some( asio::buffer(first_pdu) ) );
		REQUIRE( first_pdu.size() == written );
	}

	{
		std::array< std::uint8_t, 20 > response;
		std::size_t read;
		REQUIRE_NOTHROW( read = connection.read_some( asio::buffer(response) ) );
		REQUIRE( 2u == read );
		REQUIRE( 0x5u == response[ 0 ] );
		REQUIRE( 0x2u == response[ 1 ] );
	}

	// The connection has to be closed on the other side.
	{
		std::array< std::uint8_t, 20 > data;
		asio::error_code ec;
		REQUIRE_NOTHROW( connection.read_some( asio::buffer(data), ec ) );
		REQUIRE( asio::error::eof == ec );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("no auth PDU (one byte per second)") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	chs::handler_config_values_t config_values;
	config_values.m_socks_handshake_phase_timeout = 3s;
	chs::simulator_t simulator{
			proxy_endpoint,
			config_values
	};

	asio::io_context ctx;

	asio::ip::tcp::socket connection{ ctx };
	REQUIRE_NOTHROW( connection.connect( proxy_endpoint ) );

	{
		std::array< std::uint8_t, 1 > first_pdu{ 0x5u };
		std::size_t written;
		REQUIRE_NOTHROW( written = connection.write_some( asio::buffer(first_pdu) ) );
		REQUIRE( first_pdu.size() == written );

		std::this_thread::sleep_for( 1s );
	}

	{
		std::array< std::uint8_t, 1 > first_pdu{ 0x1u };
		std::size_t written;
		REQUIRE_NOTHROW( written = connection.write_some( asio::buffer(first_pdu) ) );
		REQUIRE( first_pdu.size() == written );

		std::this_thread::sleep_for( 1s );
	}

	{
		std::array< std::uint8_t, 1 > first_pdu{ 0x2u };
		std::size_t written;
		REQUIRE_NOTHROW( written = connection.write_some( asio::buffer(first_pdu) ) );
		REQUIRE( first_pdu.size() == written );
	}

	{
		std::array< std::uint8_t, 20 > response;
		std::size_t read;
		REQUIRE_NOTHROW( read = connection.read_some( asio::buffer(response) ) );
		REQUIRE( 2u == read );
		REQUIRE( 0x5u == response[ 0 ] );
		REQUIRE( 0x2u == response[ 1 ] );
	}

	// The connection has to be closed on the other side.
	{
		std::array< std::uint8_t, 20 > data;
		asio::error_code ec;
		REQUIRE_NOTHROW( connection.read_some( asio::buffer(data), ec ) );
		REQUIRE( asio::error::eof == ec );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("wrong auth PDU version") {
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

	{
		std::array< std::uint8_t, 3 > first_pdu{ 0x5u, 0x1u, 0x2u };
		std::size_t written;
		REQUIRE_NOTHROW( written = connection.write_some( asio::buffer(first_pdu) ) );
		REQUIRE( first_pdu.size() == written );
	}

	{
		std::array< std::uint8_t, 20 > response;
		std::size_t read;
		REQUIRE_NOTHROW( read = connection.read_some( asio::buffer(response) ) );
		REQUIRE( 2u == read );
		REQUIRE( 0x5u == response[ 0 ] );
		REQUIRE( 0x2u == response[ 1 ] );
	}

	{
		std::array< std::uint8_t, 12 > data{
			0x2,
			0x4, 'u', 's', 'e', 'r',
			0x5, '1', '2', '3', '4', '5'
		};
		std::size_t written;
		REQUIRE_NOTHROW( written = connection.write_some( asio::buffer(data) ) );
		REQUIRE( data.size() == written );
	}

	// The connection has to be closed on the other side.
	{
		std::array< std::uint8_t, 20 > data;
		asio::error_code ec;
		REQUIRE_NOTHROW( connection.read_some( asio::buffer(data), ec ) );
		REQUIRE( asio::error::eof == ec );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("partial auth PDU then close connection") {
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

	{
		std::array< std::uint8_t, 3 > first_pdu{ 0x5u, 0x1u, 0x2u };
		std::size_t written;
		REQUIRE_NOTHROW( written = connection.write_some( asio::buffer(first_pdu) ) );
		REQUIRE( first_pdu.size() == written );
	}

	{
		std::array< std::uint8_t, 20 > response;
		std::size_t read;
		REQUIRE_NOTHROW( read = connection.read_some( asio::buffer(response) ) );
		REQUIRE( 2u == read );
		REQUIRE( 0x5u == response[ 0 ] );
		REQUIRE( 0x2u == response[ 1 ] );
	}

	{
		std::array< std::uint8_t, 5 > data{
			0x1,
			0x4, 'u', 's', 'e'
		};
		std::size_t written;
		REQUIRE_NOTHROW( written = connection.write_some( asio::buffer(data) ) );
		REQUIRE( data.size() == written );
	}

	connection.close();

	std::this_thread::sleep_for( 1s );

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("partial auth PDU") {
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

	{
		std::array< std::uint8_t, 3 > first_pdu{ 0x5u, 0x1u, 0x2u };
		std::size_t written;
		REQUIRE_NOTHROW( written = connection.write_some( asio::buffer(first_pdu) ) );
		REQUIRE( first_pdu.size() == written );
	}

	{
		std::array< std::uint8_t, 20 > response;
		std::size_t read;
		REQUIRE_NOTHROW( read = connection.read_some( asio::buffer(response) ) );
		REQUIRE( 2u == read );
		REQUIRE( 0x5u == response[ 0 ] );
		REQUIRE( 0x2u == response[ 1 ] );
	}

	{
		std::array< std::uint8_t, 5 > data{
			0x1,
			0x4, 'u', 's', 'e'
		};
		std::size_t written;
		REQUIRE_NOTHROW( written = connection.write_some( asio::buffer(data) ) );
		REQUIRE( data.size() == written );
	}

	// The connection has to be closed on the other side.
	{
		std::array< std::uint8_t, 20 > data;
		asio::error_code ec;
		REQUIRE_NOTHROW( connection.read_some( asio::buffer(data), ec ) );
		REQUIRE( asio::error::eof == ec );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("garbage after auth PDU") {
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

	{
		std::array< std::uint8_t, 3 > first_pdu{ 0x5u, 0x1u, 0x2u };
		std::size_t written;
		REQUIRE_NOTHROW( written = connection.write_some( asio::buffer(first_pdu) ) );
		REQUIRE( first_pdu.size() == written );
	}

	{
		std::array< std::uint8_t, 20 > response;
		std::size_t read;
		REQUIRE_NOTHROW( read = connection.read_some( asio::buffer(response) ) );
		REQUIRE( 2u == read );
		REQUIRE( 0x5u == response[ 0 ] );
		REQUIRE( 0x2u == response[ 1 ] );
	}

	{
		std::array< std::uint8_t, 28 > data{
			0x1,
			0x4, 'u', 's', 'e', 'r',
			0x5, '1', '2', '3', '4', '5', 'a', 'b', 'c',
			0x5, 0x1, 0x0,
			0x3, 0x6, 'y', 'a', '.', 'c', 'o', 'm',
			0x01, 0x00
		};
		std::size_t written;
		REQUIRE_NOTHROW( written = connection.write_some( asio::buffer(data) ) );
		REQUIRE( data.size() == written );
	}

	// Since v.0.5.0 the size of auth PDU isn't checked.
	{
		std::array< std::uint8_t, 20 > data;
		std::size_t bytes_read{};
		REQUIRE_NOTHROW( bytes_read = connection.read_some( asio::buffer(data) ) );
		REQUIRE( 2u == bytes_read );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("zero-length username/password") {
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

	{
		std::array< std::uint8_t, 3 > first_pdu{ 0x5u, 0x1u, 0x2u };
		std::size_t written;
		REQUIRE_NOTHROW( written = connection.write_some( asio::buffer(first_pdu) ) );
		REQUIRE( first_pdu.size() == written );
	}

	{
		std::array< std::uint8_t, 20 > response;
		std::size_t read;
		REQUIRE_NOTHROW( read = connection.read_some( asio::buffer(response) ) );
		REQUIRE( 2u == read );
		REQUIRE( 0x5u == response[ 0 ] );
		REQUIRE( 0x2u == response[ 1 ] );
	}

	{
		std::array< std::uint8_t, 3 > data{
			0x1,
			0x0,
			0x0
		};
		std::size_t written;
		REQUIRE_NOTHROW( written = connection.write_some( asio::buffer(data) ) );
		REQUIRE( data.size() == written );
	}

	{
		std::array< std::uint8_t, 20 > response;
		std::size_t read;
		REQUIRE_NOTHROW( read = connection.read_some( asio::buffer(response) ) );
		REQUIRE( 2u == read );
		REQUIRE( 0x1u == response[ 0 ] );
		REQUIRE( 0x0u == response[ 1 ] );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("valid auth PDU") {
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

	{
		std::array< std::uint8_t, 3 > first_pdu{ 0x5u, 0x1u, 0x2u };
		std::size_t written;
		REQUIRE_NOTHROW( written = connection.write_some( asio::buffer(first_pdu) ) );
		REQUIRE( first_pdu.size() == written );
	}

	{
		std::array< std::uint8_t, 20 > response;
		std::size_t read;
		REQUIRE_NOTHROW( read = connection.read_some( asio::buffer(response) ) );
		REQUIRE( 2u == read );
		REQUIRE( 0x5u == response[ 0 ] );
		REQUIRE( 0x2u == response[ 1 ] );
	}

	{
		std::array< std::uint8_t, 12 > data{
			0x1,
			0x4, 'u', 's', 'e', 'r',
			0x5, '1', '2', '3', '4', '5'
		};
		std::size_t written;
		REQUIRE_NOTHROW( written = connection.write_some( asio::buffer(data) ) );
		REQUIRE( data.size() == written );
	}

	{
		std::array< std::uint8_t, 20 > response;
		std::size_t read;
		REQUIRE_NOTHROW( read = connection.read_some( asio::buffer(response) ) );
		REQUIRE( 2u == read );
		REQUIRE( 0x1u == response[ 0 ] );
		REQUIRE( 0x0u == response[ 1 ] );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("auth method with auth PDU as one package") {
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

	{
		std::array< std::uint8_t, 15 > first_pdu{
			0x5u, 0x1u, 0x2u, // Auth method selection.
			0x1, // Auth PDU.
			0x4, 'u', 's', 'e', 'r',
			0x5, '1', '2', '3', '4', '5'
		};
		std::size_t written;
		REQUIRE_NOTHROW( written = connection.write_some( asio::buffer(first_pdu) ) );
		REQUIRE( first_pdu.size() == written );
	}

	{
		std::array< std::uint8_t, 2 > response;
		std::size_t read;
		REQUIRE_NOTHROW( read = connection.read_some( asio::buffer(response) ) );
		REQUIRE( 2u == read );
		REQUIRE( 0x5u == response[ 0 ] );
		REQUIRE( 0x2u == response[ 1 ] );
	}

	{
		std::array< std::uint8_t, 20 > response;
		std::size_t read;
		REQUIRE_NOTHROW( read = connection.read_some( asio::buffer(response) ) );
		REQUIRE( 2u == read );
		REQUIRE( 0x1u == response[ 0 ] );
		REQUIRE( 0x0u == response[ 1 ] );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

