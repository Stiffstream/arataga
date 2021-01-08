#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN 
#include <doctest/doctest.h>

#include <arataga/acl_handler/buffers.hpp>

#include <tests/connection_handler_simulator/pub.hpp>

#include <asio.hpp>

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

void
write_bind_pdu(
	asio::ip::tcp::socket & connection,
	std::string_view host_name,
	std::uint16_t port )
{
	{
		arataga::acl_handler::out_buffer_fixed_t<
				1 // VER
				+ 1 // CMD
				+ 1 // RESERVED
				+ 1 // ATYP
				+ 256 // DST.ADDR (это максимальная возможная длина).
				+ 2 // DST.PORT
			> data;

		data.write_byte( std::byte{0x5u} );
		data.write_byte( std::byte{0x2u} );
		data.write_byte( std::byte{0u} );
		data.write_byte( std::byte{0x3u} ); // ATYP

		// domain name length.
		data.write_byte( std::byte{ static_cast<std::uint8_t>(host_name.size()) } );
		// domain name.
		data.write_string( host_name );

		// DST.PORT
		data.write_byte(
				std::byte{ static_cast<std::uint8_t>(port >> 8) } );
		data.write_byte(
				std::byte{ static_cast<std::uint8_t>(port & 0xff) } );

		REQUIRE_NOTHROW( asio::write( connection, data.asio_buffer() ) );
	}
}

TEST_CASE("no connection from target-end") {
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

	write_auth_pdu( connection, "user", "12345" );
	write_bind_pdu( connection, "localhost", 3333 );

	// Должны прочитать положительный ответ.
	{
		std::array< std::uint8_t,
				1 // VER
				+ 1 // REP
				+ 1 // RESERVED
				+ 1 // ATYP
				+ 4 // DST.ADDR (IPv4).
				+ 2 // DST.PORT
			> data;

		std::size_t read;
		REQUIRE_NOTHROW( read = connection.read_some( asio::buffer(data) ) );
		REQUIRE( 10u == read );
		REQUIRE( 0x5u == data[ 0 ] );
		REQUIRE( 0x0u == data[ 1 ] );
		REQUIRE( 0x0u == data[ 2 ] );
		REQUIRE( 0x1u == data[ 3 ] );
		REQUIRE( 0x7fu == data[ 4 ] );
		REQUIRE( 0x0u == data[ 5 ] );
		REQUIRE( 0x0u == data[ 6 ] );
		REQUIRE( 0x1u == data[ 7 ] );
	}

	chs::dump_trace( (std::cout << "***\n"), simulator.get_trace() );

	// Далее должны прочитать отрицательный ответ.
	{
		std::array< std::uint8_t,
				1 // VER
				+ 1 // REP
				+ 1 // RESERVED
				+ 1 // ATYP
				+ 4 // DST.ADDR (IPv4).
				+ 2 // DST.PORT
			> data;

		std::size_t read;
		REQUIRE_NOTHROW( read = connection.read_some( asio::buffer(data) ) );
		REQUIRE( 4u == read );
		REQUIRE( 0x5u == data[ 0 ] );
		REQUIRE( 0x4u == data[ 1 ] );
		REQUIRE( 0x0u == data[ 2 ] );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("connection from target-end") {
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

	write_auth_pdu( connection, "user", "12345" );
	write_bind_pdu( connection, "localhost", 3333 );

	chs::dump_trace( (std::cout << "***\n"), simulator.get_trace() );

	// Должны прочитать положительный ответ.
	std::uint16_t listening_port{ 0u };
	{
		std::array< std::uint8_t,
				1 // VER
				+ 1 // REP
				+ 1 // RESERVED
				+ 1 // ATYP
				+ 4 // DST.ADDR (IPv4).
				+ 2 // DST.PORT
			> data;

		std::size_t read;
		REQUIRE_NOTHROW( read = connection.read_some( asio::buffer(data) ) );
		REQUIRE( 10u == read );
		REQUIRE( 0x5u == data[ 0 ] );
		REQUIRE( 0x0u == data[ 1 ] );
		REQUIRE( 0x0u == data[ 2 ] );
		REQUIRE( 0x1u == data[ 3 ] );
		REQUIRE( 0x7fu == data[ 4 ] );
		REQUIRE( 0x0u == data[ 5 ] );
		REQUIRE( 0x0u == data[ 6 ] );
		REQUIRE( 0x1u == data[ 7 ] );

		listening_port = (static_cast<std::uint16_t>(data[8]) << 8) |
				static_cast<std::uint16_t>(data[9]);

		std::cout << "=====\n => listening port: " << listening_port << std::endl;
	}

	chs::dump_trace( (std::cout << "***\n"), simulator.get_trace() );

	asio::ip::tcp::socket incoming{ ctx };

	REQUIRE_NOTHROW( incoming.connect(
			asio::ip::tcp::endpoint{
				asio::ip::make_address( "127.0.0.1" ),
				listening_port
			} )
	);

	// Далее должны прочитать отрицательный ответ.
	{
		std::array< std::uint8_t,
				1 // VER
				+ 1 // REP
				+ 1 // RESERVED
				+ 1 // ATYP
				+ 4 // DST.ADDR (IPv4).
				+ 2 // DST.PORT
			> data;

		std::size_t read;
		REQUIRE_NOTHROW( read = connection.read_some( asio::buffer(data) ) );
		REQUIRE( 10u == read );
		REQUIRE( 0x5u == data[ 0 ] );
		REQUIRE( 0x0u == data[ 1 ] );
		REQUIRE( 0x0u == data[ 2 ] );
	}

	chs::dump_trace( (std::cout << "***\n"), simulator.get_trace() );

	{
		std::array< char, 6 > data{ 'H', 'e', 'l', 'l', 'o', '?' };
		REQUIRE_NOTHROW( asio::write( connection, asio::buffer(data) ) );
	}

	{
		std::array< char, 6 > data;
		const std::array< char, 6 > expected{ 'H', 'e', 'l', 'l', 'o', '?' };
		REQUIRE_NOTHROW( asio::read( incoming, asio::buffer(data) ) );
		REQUIRE( data == expected );
	}

	{
		std::array< char, 6 > data{ 'W', 'o', 'r', 'l', 'd', '!' };
		REQUIRE_NOTHROW( asio::write( incoming, asio::buffer(data) ) );
	}

	{
		std::array< char, 6 > data;
		const std::array< char, 6 > expected{ 'W', 'o', 'r', 'l', 'd', '!' };
		REQUIRE_NOTHROW( asio::read( connection, asio::buffer(data) ) );
		REQUIRE( data == expected );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

