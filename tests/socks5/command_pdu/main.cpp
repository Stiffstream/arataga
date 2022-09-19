#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN 
#include <doctest/doctest.h>

#include <arataga/acl_handler/buffers.hpp>

#include <tests/connection_handler_simulator/pub.hpp>

#include <asio.hpp>

#include <thread>

using namespace std::string_view_literals;
using namespace std::chrono_literals;

namespace chs = connection_handler_simulator;

void
write_auth_pdu(
	asio::ip::tcp::socket & connection,
	std::string username = "user",
	std::string password = "1234" )
{
	{
		std::array< std::uint8_t, 3 > first_pdu{ 0x5u, 0x1u, 0x2u };
		REQUIRE_NOTHROW( asio::write( connection, asio::buffer(first_pdu) ) );
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
		arataga::acl_handler::out_buffer_fixed_t< 1u + 1u + 255u + 1u + 255u >
				data;

		data.write_byte( std::byte{0x1u} );
		data.write_byte( std::byte{ static_cast<std::uint8_t>(username.size()) } );
		data.write_string( username );
		data.write_byte( std::byte{ static_cast<std::uint8_t>(password.size()) } );
		data.write_string( password );

		REQUIRE_NOTHROW( asio::write( connection, data.asio_buffer() ) );
	}

	{
		std::array< std::uint8_t, 20 > response;
		std::size_t read;
		REQUIRE_NOTHROW( read = connection.read_some( asio::buffer(response) ) );
		REQUIRE( 2u == read );
		REQUIRE( 0x1u == response[ 0 ] );
		REQUIRE( 0x0u == response[ 1 ] );
	}
}

TEST_CASE("no command PDU") {
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

	write_auth_pdu( connection );

	// The connection has to be closed on the other side.
	{
		std::array< std::uint8_t, 20 > data;
		asio::error_code ec;
		REQUIRE_NOTHROW( connection.read_some( asio::buffer(data), ec ) );
		REQUIRE( asio::error::eof == ec );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("partial command PDU") {
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

	write_auth_pdu( connection );

	{
		std::array< std::uint8_t, 10u > data{
			0x5, 0x1, 0x0,
			0x3, 0x5, 'y', 'a', '.', 'r', 'u'
		};

		REQUIRE_NOTHROW( asio::write(connection, asio::buffer(data)) );
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

TEST_CASE("command PDU with unsupported ATYP") {
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

	write_auth_pdu( connection );

	{
		std::array< std::uint8_t, 12u > data{
			0x5, 0x1, 0x0,
			0x6, 0x5, 'y', 'a', '.', 'r', 'u',
			0x01, 0x00
		};

		REQUIRE_NOTHROW( asio::write(connection, asio::buffer(data)) );
	}

	// A negative response is expected.
	{
		std::array< std::uint8_t, 4 > data;
		REQUIRE_NOTHROW( asio::read(connection, asio::buffer(data)) );
		const std::array< std::uint8_t, 4 > expected{ 0x5, 0x8, 0x0, 0x0 };
		REQUIRE( expected == data );
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

TEST_CASE("command PDU with empty domain name") {
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

	write_auth_pdu( connection );

	{
		std::array< std::uint8_t, 7u > data{
			0x5, 0x1, 0x0,
			0x3, 0x0,
			0x01, 0x00
		};

		REQUIRE_NOTHROW( asio::write(connection, asio::buffer(data)) );
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

TEST_CASE("slow send") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	chs::handler_config_values_t config_values;
	config_values.m_socks_handshake_phase_timeout = 15s;

	chs::simulator_t simulator{
			proxy_endpoint,
			config_values
	};

	asio::io_context ctx;

	asio::ip::tcp::socket connection{ ctx };

	REQUIRE_NOTHROW( connection.connect( proxy_endpoint ) );

	asio::ip::tcp::no_delay no_delay_opt{ true };
	connection.set_option( no_delay_opt );

	write_auth_pdu( connection );

	{
		std::array< std::uint8_t, 12u > data{
			0x5, 0x4, 0x0,
			0x3, 0x5, 'y', 'a', '.', 'r', 'u',
			0x01, 0x00
		};

		for( auto b : data )
		{
			std::this_thread::sleep_for( 125ms );
			std::array< std::uint8_t, 1u > to_send{ b };
			REQUIRE_NOTHROW( asio::write(connection, asio::buffer(to_send)) );
			std::cout << "." << std::flush;
		}

		std::cout << std::endl;
	}

	// A negative response is expected.
	{
		std::array< std::uint8_t, 4 > data;
		REQUIRE_NOTHROW( asio::read(connection, asio::buffer(data)) );
		const std::array< std::uint8_t, 4 > expected{ 0x5, 0x7, 0x0, 0x0 };
		REQUIRE_NOTHROW( expected == data );
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

TEST_CASE("connect command with unknown hostname") {
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

	// Now the user name should be correct.
	write_auth_pdu( connection, "user", "12345" );

	{
		std::array< std::uint8_t, 13u > data{
			0x5, 0x1, 0x0,
			0x3, 0x6, 'y', 'a', '.', 'c', 'o', 'm',
			0x01, 0x00
		};

		REQUIRE_NOTHROW( asio::write(connection, asio::buffer(data)) );
	}

	// A negative response is expected.
	{
		std::array< std::uint8_t, 4 > data;
		REQUIRE_NOTHROW( asio::read(connection, asio::buffer(data)) );
		const std::array< std::uint8_t, 4 > expected{ 0x5, 0x4, 0x0, 0x0 };
		REQUIRE( expected == data );
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

TEST_CASE("connect command with unknown user") {
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

	write_auth_pdu( connection, "not-a-valid-user", "invalid-password" );

	{
		std::array< std::uint8_t, 12u > data{
			0x5, 0x1, 0x0,
			0x3, 0x5, 'y', 'a', '.', 'r', 'u',
			0x01, 0x00
		};

		REQUIRE_NOTHROW( asio::write(connection, asio::buffer(data)) );
	}

	// A negative response is expected.
	{
		std::array< std::uint8_t, 4 > data;
		REQUIRE_NOTHROW( asio::read(connection, asio::buffer(data)) );
		const std::array< std::uint8_t, 4 > expected{ 0x5, 0x2, 0x0, 0x0 };
		REQUIRE( expected == data );
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

