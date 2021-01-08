#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN 
#include <doctest/doctest.h>

#include <arataga/acl_handler/buffers.hpp>

#include <restinio/helpers/string_algo.hpp>

#include <tests/connection_handler_simulator/pub.hpp>

#include <asio.hpp>

using namespace std::string_view_literals;
using namespace std::chrono_literals;

namespace chs = connection_handler_simulator;

TEST_CASE("headers without the body") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	chs::handler_config_values_t config_values;
	config_values.m_http_headers_complete_timeout = 2s;

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
			"Connection: Keep-Alive\r\n"
			"Cache-Control: no-cache\r\n"
			"Accept: */*\r\n"
		};

		REQUIRE_NOTHROW( asio::write(connection,
				asio::buffer(outgoing_request)) );
	}

	// Должны прочитать отрицательный ответ.
	{
		std::array< char, 512 > data;
		std::size_t bytes_read;
		REQUIRE_NOTHROW( bytes_read = connection.read_some(asio::buffer(data)) );
		std::string_view response{ &data[ 0 ], bytes_read };
		REQUIRE( restinio::string_algo::starts_with(
				response, "HTTP/1.1 408 Request Timeout\r\n"sv ) );
	}

	// Соединение должно быть закрыто на другой стороне.
	{
		std::array< std::uint8_t, 20 > data;
		asio::error_code ec;
		REQUIRE_NOTHROW( connection.read_some( asio::buffer(data), ec ) );
		REQUIRE( asio::error::eof == ec );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("severals Host headers") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	chs::handler_config_values_t config_values;
	config_values.m_http_headers_complete_timeout = 2s;

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
			"Host: localhost\r\n"
			"Connection: Keep-Alive\r\n"
			"Cache-Control: no-cache\r\n"
			"Host: localhost:8080\r\n"
			"Accept: */*\r\n"
			"Content-Length: 0\r\n"
			"\r\n"
		};

		REQUIRE_NOTHROW( asio::write(connection,
				asio::buffer(outgoing_request)) );
	}

	// Должны прочитать отрицательный ответ.
	{
		std::array< char, 512 > data;
		std::size_t bytes_read;
		REQUIRE_NOTHROW( bytes_read = connection.read_some(asio::buffer(data)) );
		std::string_view response{ &data[ 0 ], bytes_read };
		REQUIRE( restinio::string_algo::starts_with(
				response, "HTTP/1.1 400 Bad Request\r\n"sv ) );
	}

	// Соединение должно быть закрыто на другой стороне.
	{
		std::array< std::uint8_t, 20 > data;
		asio::error_code ec;
		REQUIRE_NOTHROW( connection.read_some( asio::buffer(data), ec ) );
		REQUIRE( asio::error::eof == ec );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("request-target too long") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	chs::handler_config_values_t config_values;
	config_values.m_http_message_limits.m_max_request_target_length = 100u;

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
			"GET /123456789/123456789/123456789/123456789/123456789/123456789/"
				"123456789/123456789/123456789/123456789/123456789/123456789 "
				"HTTP/1.1\r\n"
			"Host: localhost\r\n"
			"Connection: Keep-Alive\r\n"
			"Cache-Control: no-cache\r\n"
			"Host: localhost:8080\r\n"
			"Accept: */*\r\n"
			"Content-Length: 0\r\n"
			"\r\n"
		};

		REQUIRE_NOTHROW( asio::write(connection,
				asio::buffer(outgoing_request)) );
	}

	// Должны прочитать отрицательный ответ.
	{
		std::array< char, 512 > data;
		std::size_t bytes_read;
		REQUIRE_NOTHROW( bytes_read = connection.read_some(asio::buffer(data)) );
		std::string_view response{ &data[ 0 ], bytes_read };
		REQUIRE( restinio::string_algo::starts_with(
				response, "HTTP/1.1 400 Bad Request\r\n"sv ) );
	}

	// Соединение должно быть закрыто на другой стороне.
	{
		std::array< std::uint8_t, 20 > data;
		asio::error_code ec;
		REQUIRE_NOTHROW( connection.read_some( asio::buffer(data), ec ) );
		REQUIRE( asio::error::eof == ec );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("HTTP-field name too long") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	chs::handler_config_values_t config_values;
	config_values.m_http_message_limits.m_max_field_name_length = 100u;

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
			"Host: localhost\r\n"
			"Connection: Keep-Alive\r\n"
			"Cache-Control: no-cache\r\n"
			"Host: localhost:8080\r\n"
			"Header-With-Very-Very-Long-Name-123456789"
			"-123456789-123456789-123456789-123456789-123456789"
			"-123456789-123456789-123456789-123456789-123456789: Boo!\r\n"
			"Accept: */*\r\n"
			"Content-Length: 0\r\n"
			"\r\n"
		};

		REQUIRE_NOTHROW( asio::write(connection,
				asio::buffer(outgoing_request)) );
	}

	// Должны прочитать отрицательный ответ.
	{
		std::array< char, 512 > data;
		std::size_t bytes_read;
		REQUIRE_NOTHROW( bytes_read = connection.read_some(asio::buffer(data)) );
		std::string_view response{ &data[ 0 ], bytes_read };
		REQUIRE( restinio::string_algo::starts_with(
				response, "HTTP/1.1 400 Bad Request\r\n"sv ) );
	}

	// Соединение должно быть закрыто на другой стороне.
	{
		std::array< std::uint8_t, 20 > data;
		asio::error_code ec;
		REQUIRE_NOTHROW( connection.read_some( asio::buffer(data), ec ) );
		REQUIRE( asio::error::eof == ec );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("HTTP-field value too long") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	chs::handler_config_values_t config_values;
	config_values.m_http_message_limits.m_max_field_value_length = 100u;

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
			"Host: localhost\r\n"
			"Connection: Keep-Alive\r\n"
			"Cache-Control: no-cache\r\n"
			"Host: localhost:8080\r\n"
			"Header-With-Very-Very-Long-Value: 123456789"
			"-123456789-123456789-123456789-123456789-123456789"
			"-123456789-123456789-123456789-123456789-123456789 Boo!\r\n"
			"Accept: */*\r\n"
			"Content-Length: 0\r\n"
			"\r\n"
		};

		REQUIRE_NOTHROW( asio::write(connection,
				asio::buffer(outgoing_request)) );
	}

	// Должны прочитать отрицательный ответ.
	{
		std::array< char, 512 > data;
		std::size_t bytes_read;
		REQUIRE_NOTHROW( bytes_read = connection.read_some(asio::buffer(data)) );
		std::string_view response{ &data[ 0 ], bytes_read };
		REQUIRE( restinio::string_algo::starts_with(
				response, "HTTP/1.1 400 Bad Request\r\n"sv ) );
	}

	// Соединение должно быть закрыто на другой стороне.
	{
		std::array< std::uint8_t, 20 > data;
		asio::error_code ec;
		REQUIRE_NOTHROW( connection.read_some( asio::buffer(data), ec ) );
		REQUIRE( asio::error::eof == ec );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("total http-fields size too big") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	chs::handler_config_values_t config_values;
	config_values.m_http_message_limits.m_max_total_headers_size = 100u;

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
			"Host: localhost\r\n"
			"Connection: Keep-Alive\r\n"
			"Cache-Control: no-cache\r\n"
			"Host: localhost:8080\r\n"
			"Accept: */*\r\n"
			"Content-Length: 0\r\n"
			"Dummy-Header-1: 01234567890123456789\r\n"
			"Dummy-Header-2: 01234567890123456789\r\n"
			"Dummy-Header-3: 01234567890123456789\r\n"
			"Dummy-Header-4: 01234567890123456789\r\n"
			"Dummy-Header-5: 01234567890123456789\r\n"
			"Dummy-Header-6: 01234567890123456789\r\n"
			"\r\n"
		};

		REQUIRE_NOTHROW( asio::write(connection,
				asio::buffer(outgoing_request)) );
	}

	// Должны прочитать отрицательный ответ.
	{
		std::array< char, 512 > data;
		std::size_t bytes_read;
		REQUIRE_NOTHROW( bytes_read = connection.read_some(asio::buffer(data)) );
		std::string_view response{ &data[ 0 ], bytes_read };
		REQUIRE( restinio::string_algo::starts_with(
				response, "HTTP/1.1 400 Bad Request\r\n"sv ) );
	}

	// Соединение должно быть закрыто на другой стороне.
	{
		std::array< std::uint8_t, 20 > data;
		asio::error_code ec;
		REQUIRE_NOTHROW( connection.read_some( asio::buffer(data), ec ) );
		REQUIRE( asio::error::eof == ec );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

