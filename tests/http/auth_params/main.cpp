#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN 
#include <doctest/doctest.h>

#include <arataga/acl_handler/buffers.hpp>

#include <restinio/helpers/string_algo.hpp>

#include <tests/connection_handler_simulator/pub.hpp>

#include <asio.hpp>

using namespace std::string_view_literals;
using namespace std::chrono_literals;

namespace chs = connection_handler_simulator;

TEST_CASE("invalid value (no username/password in Proxy-Authorization)") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	chs::handler_config_values_t config_values;
	config_values.m_http_headers_complete_timeout = 250ms;

	chs::simulator_t simulator{
			proxy_endpoint,
			config_values
	};

	asio::io_context ctx;

	asio::ip::tcp::socket connection{ ctx };

	REQUIRE_NOTHROW( connection.connect( proxy_endpoint ) );

	asio::ip::tcp::no_delay no_delay_opt{ true };
	connection.set_option( no_delay_opt );

	{
		std::string_view outgoing_request{
			"GET http://localhost:8080/ HTTP/1.1\r\n"
			"Host: localhost\r\n"
			"Proxy-Authorization: Basic\r\n"
			"\r\n"
		};

		REQUIRE_NOTHROW( asio::write(connection,
				asio::buffer(outgoing_request)) );
	}

	// Negative response is expected.
	{
		std::array< char, 512 > data;
		std::size_t bytes_read;
		REQUIRE_NOTHROW( bytes_read = connection.read_some(asio::buffer(data)) );
		std::string_view response{ &data[ 0 ], bytes_read };
		REQUIRE( restinio::string_algo::starts_with(
				response, "HTTP/1.1 400 Bad Request\r\n"sv ) );
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

TEST_CASE("invalid value (garbage instead username/password in "
		"Proxy-Authorization)") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	chs::handler_config_values_t config_values;
	config_values.m_http_headers_complete_timeout = 250ms;

	chs::simulator_t simulator{
			proxy_endpoint,
			config_values
	};

	asio::io_context ctx;

	asio::ip::tcp::socket connection{ ctx };

	REQUIRE_NOTHROW( connection.connect( proxy_endpoint ) );

	asio::ip::tcp::no_delay no_delay_opt{ true };
	connection.set_option( no_delay_opt );

	{
		std::string_view outgoing_request{
			"GET http://localhost:8080/ HTTP/1.1\r\n"
			"Host: localhost\r\n"
			"Proxy-Authorization: Basic bla-bla-bla\r\n"
			"\r\n"
		};

		REQUIRE_NOTHROW( asio::write(connection,
				asio::buffer(outgoing_request)) );
	}

	// A negative response is expected.
	{
		std::array< char, 512 > data;
		std::size_t bytes_read;
		REQUIRE_NOTHROW( bytes_read = connection.read_some(asio::buffer(data)) );
		std::string_view response{ &data[ 0 ], bytes_read };
		REQUIRE( restinio::string_algo::starts_with(
				response, "HTTP/1.1 400 Bad Request\r\n"sv ) );
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

TEST_CASE("no basic-auth") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	chs::handler_config_values_t config_values;
	config_values.m_http_headers_complete_timeout = 250ms;

	chs::simulator_t simulator{
			proxy_endpoint,
			config_values
	};

	asio::io_context ctx;

	asio::ip::tcp::socket connection{ ctx };

	REQUIRE_NOTHROW( connection.connect( proxy_endpoint ) );

	asio::ip::tcp::no_delay no_delay_opt{ true };
	connection.set_option( no_delay_opt );

	{
		std::string_view outgoing_request{
			"GET http://localhost:8080/ HTTP/1.1\r\n"
			"Host: localhost\r\n"
			"Proxy-Authorization: Bearer bla-bla-bla\r\n"
			"\r\n"
		};

		REQUIRE_NOTHROW( asio::write(connection,
				asio::buffer(outgoing_request)) );
	}

	// A negative response is expected.
	{
		std::array< char, 512 > data;
		std::size_t bytes_read;
		REQUIRE_NOTHROW( bytes_read = connection.read_some(asio::buffer(data)) );
		std::string_view response{ &data[ 0 ], bytes_read };
		REQUIRE( restinio::string_algo::starts_with(
				response, "HTTP/1.1 400 Bad Request\r\n"sv ) );
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

TEST_CASE("no target-host and port") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	chs::handler_config_values_t config_values;
	config_values.m_http_headers_complete_timeout = 250ms;

	chs::simulator_t simulator{
			proxy_endpoint,
			config_values
	};

	asio::io_context ctx;

	asio::ip::tcp::socket connection{ ctx };

	REQUIRE_NOTHROW( connection.connect( proxy_endpoint ) );

	asio::ip::tcp::no_delay no_delay_opt{ true };
	connection.set_option( no_delay_opt );

	{
		std::string_view outgoing_request{
			"GET / HTTP/1.1\r\n"
			"Proxy-Authorization: Basic dXNlcjoxMjM0NQ==\r\n"
			"\r\n"
		};

		REQUIRE_NOTHROW( asio::write(connection,
				asio::buffer(outgoing_request)) );
	}

	// A negative response is expected.
	{
		std::array< char, 512 > data;
		std::size_t bytes_read;
		REQUIRE_NOTHROW( bytes_read = connection.read_some(asio::buffer(data)) );
		std::string_view response{ &data[ 0 ], bytes_read };
		REQUIRE( restinio::string_algo::starts_with(
				response, "HTTP/1.1 400 Bad Request\r\n"sv ) );
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

TEST_CASE("empty value of Host HTTP-field") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	chs::handler_config_values_t config_values;
	config_values.m_http_headers_complete_timeout = 250ms;

	chs::simulator_t simulator{
			proxy_endpoint,
			config_values
	};

	asio::io_context ctx;

	asio::ip::tcp::socket connection{ ctx };

	REQUIRE_NOTHROW( connection.connect( proxy_endpoint ) );

	asio::ip::tcp::no_delay no_delay_opt{ true };
	connection.set_option( no_delay_opt );

	{
		std::string_view outgoing_request{
			"GET / HTTP/1.1\r\n"
			"Host:\r\n"
			"Proxy-Authorization: Basic dXNlcjoxMjM0NQ==\r\n"
			"\r\n"
		};

		REQUIRE_NOTHROW( asio::write(connection,
				asio::buffer(outgoing_request)) );
	}

	// A negative response is expected.
	{
		std::array< char, 512 > data;
		std::size_t bytes_read;
		REQUIRE_NOTHROW( bytes_read = connection.read_some(asio::buffer(data)) );
		std::string_view response{ &data[ 0 ], bytes_read };
		REQUIRE( restinio::string_algo::starts_with(
				response, "HTTP/1.1 400 Bad Request\r\n"sv ) );
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

TEST_CASE("invalue value of Host HTTP-field") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	chs::handler_config_values_t config_values;
	config_values.m_http_headers_complete_timeout = 250ms;

	chs::simulator_t simulator{
			proxy_endpoint,
			config_values
	};

	asio::io_context ctx;

	asio::ip::tcp::socket connection{ ctx };

	REQUIRE_NOTHROW( connection.connect( proxy_endpoint ) );

	asio::ip::tcp::no_delay no_delay_opt{ true };
	connection.set_option( no_delay_opt );

	{
		std::string_view outgoing_request{
			"GET / HTTP/1.1\r\n"
			"Host: some arbitrary value\r\n"
			"Proxy-Authorization: Basic dXNlcjoxMjM0NQ==\r\n"
			"\r\n"
		};

		REQUIRE_NOTHROW( asio::write(connection,
				asio::buffer(outgoing_request)) );
	}

	// A negative response is expected.
	{
		std::array< char, 512 > data;
		std::size_t bytes_read;
		REQUIRE_NOTHROW( bytes_read = connection.read_some(asio::buffer(data)) );
		std::string_view response{ &data[ 0 ], bytes_read };
		REQUIRE( restinio::string_algo::starts_with(
				response, "HTTP/1.1 400 Bad Request\r\n"sv ) );
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

