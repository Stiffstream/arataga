#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN 
#include <doctest/doctest.h>

#include <arataga/acl_handler/buffers.hpp>

#include <restinio/helpers/string_algo.hpp>

#include <so_5/details/at_scope_exit.hpp>

#include <tests/connection_handler_simulator/pub.hpp>

#include <asio.hpp>

using namespace std::string_view_literals;
using namespace std::chrono_literals;

namespace chs = connection_handler_simulator;

TEST_CASE("Normal request without trailing headers") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	asio::io_context target_context;
	asio::ip::tcp::acceptor acceptor{
			target_context,
			asio::ip::tcp::endpoint{
					asio::ip::make_address_v4( "127.0.0.1" ),
					9090
				},
			true 
		};
	std::thread target_processing_thread{
		[&target_context, &acceptor]() {
			asio::ip::tcp::socket incoming{ target_context };

			asio::error_code ec;
			acceptor.accept( incoming, ec );
			if( ec )
				return;

			std::string data;
			asio::read_until(
					incoming, asio::dynamic_buffer(data), "\r\n0\r\n\r\n"sv, ec );
			if( ec )
				return;

			asio::write( incoming,
					asio::buffer( "HTTP/1.1 200 OK\r\n\r\n"sv ),
					ec );
		} };
	auto target_processing_thread_joiner = so_5::details::at_scope_exit(
			[&target_processing_thread] {
				target_processing_thread.join();
			} );
	auto acceptor_closer = so_5::details::at_scope_exit(
			[&target_context, &acceptor] {
				acceptor.close();
			} );

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
			"POST http://localhost:9090/ HTTP/1.1\r\n"
			"Host: localhost:9090\r\n"
			"Transfer-Encoding: chunked\r\n"
			"My-Empty-Header:\r\n"
			"My-Non-Empty-Header: dummy\r\n"
			"Proxy-Authorization: basic dXNlcjoxMjM0NQ==\r\n"
			"\r\n"
			"4\r\n"
			"Wiki\r\n"
			"5;Ext-One;Ext-Two=Ext-Two-Value;Ext-Three=\"Ext Three Value\"\r\n"
			"pedia\r\n"
			"E\r\n"
			" in\r\n"
			"\r\n"
			"chunks.\r\n"
			"0\r\n"
			"\r\n"
		};

		REQUIRE_NOTHROW( asio::write(connection,
				asio::buffer(outgoing_request)) );
	}

	// Должны прочитать положительный ответ.
	{
		std::array< char, 512 > data;
		std::size_t bytes_read;
		REQUIRE_NOTHROW( bytes_read = connection.read_some(asio::buffer(data)) );
		std::string_view response{ &data[ 0 ], bytes_read };
		std::cout << response << std::endl;
		REQUIRE( restinio::string_algo::starts_with(
				response, "HTTP/1.1 200 OK"sv ) );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("Request with trailing headers") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	asio::io_context target_context;
	asio::ip::tcp::acceptor acceptor{
			target_context,
			asio::ip::tcp::endpoint{
					asio::ip::make_address_v4( "127.0.0.1" ),
					9090
				},
			true 
		};
	std::thread target_processing_thread{
		[&target_context, &acceptor]() {
			asio::ip::tcp::socket incoming{ target_context };

			asio::error_code ec;
			acceptor.accept( incoming, ec );
			if( ec )
				return;

			std::string data;
			asio::read_until(
					incoming, asio::dynamic_buffer(data), "\r\n0\r\n\r\n"sv, ec );
			if( ec )
				return;

			asio::write( incoming,
					asio::buffer( "HTTP/1.1 200 OK\r\n\r\n"sv ),
					ec );
		} };
	auto target_processing_thread_joiner = so_5::details::at_scope_exit(
			[&target_processing_thread] {
				target_processing_thread.join();
			} );
	auto acceptor_closer = so_5::details::at_scope_exit(
			[&target_context, &acceptor] {
				acceptor.close();
			} );

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
			"POST http://localhost:9090/ HTTP/1.1\r\n"
			"Host: localhost:9090\r\n"
			"Transfer-Encoding: chunked\r\n"
			"My-Empty-Header:\r\n"
			"My-Non-Empty-Header: dummy\r\n"
			"Proxy-Authorization: basic dXNlcjoxMjM0NQ==\r\n"
			"\r\n"
			"4\r\n"
			"Wiki\r\n"
			"5;Ext-One;Ext-Two=Ext-Two-Value;Ext-Three=\"Ext Three Value\"\r\n"
			"pedia\r\n"
			"E\r\n"
			" in\r\n"
			"\r\n"
			"chunks.\r\n"
			"0\r\n"
			"Post-Chunked-Body-Header-1: Value1\r\n"
			"Post-Chunked-Body-Header-2: Value2\r\n"
			"\r\n"
		};

		REQUIRE_NOTHROW( asio::write(connection,
				asio::buffer(outgoing_request)) );
	}

	// Должны прочитать положительный ответ.
	{
		std::array< char, 512 > data;
		std::size_t bytes_read;
		REQUIRE_NOTHROW( bytes_read = connection.read_some(asio::buffer(data)) );
		std::string_view response{ &data[ 0 ], bytes_read };
		std::cout << response << std::endl;
		REQUIRE( restinio::string_algo::starts_with(
				response, "HTTP/1.1 200 OK"sv ) );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("Response with trailing headers") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	asio::io_context target_context;
	asio::ip::tcp::acceptor acceptor{
			target_context,
			asio::ip::tcp::endpoint{
					asio::ip::make_address_v4( "127.0.0.1" ),
					9090
				},
			true 
		};
	std::thread target_processing_thread{
		[&target_context, &acceptor]() {
			asio::ip::tcp::socket incoming{ target_context };

			asio::error_code ec;
			acceptor.accept( incoming, ec );
			if( ec )
				return;

			std::string data;
			asio::read_until(
					incoming, asio::dynamic_buffer(data), "\r\n0\r\n\r\n"sv, ec );
			if( ec )
				return;

			asio::write( incoming,
					asio::buffer(
							"HTTP/1.1 200 OK\r\n"
							"Transfer-Encoding: chunked\r\n"
							"\r\n"
							"5\r\n"
							"12345\r\n"
							"4\r\n"
							"6789\r\n"
							"0\r\n"
							"Trailing-Header-1: Value\r\n"
							"Trailing-Header-2: Value-2\r\n"
							"\r\n"sv ),
					ec );
		} };
	auto target_processing_thread_joiner = so_5::details::at_scope_exit(
			[&target_processing_thread] {
				target_processing_thread.join();
			} );
	auto acceptor_closer = so_5::details::at_scope_exit(
			[&target_context, &acceptor] {
				acceptor.close();
			} );

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
			"POST http://localhost:9090/ HTTP/1.1\r\n"
			"Host: localhost:9090\r\n"
			"Transfer-Encoding: chunked\r\n"
			"My-Empty-Header:\r\n"
			"My-Non-Empty-Header: dummy\r\n"
			"Proxy-Authorization: basic dXNlcjoxMjM0NQ==\r\n"
			"\r\n"
			"4\r\n"
			"Wiki\r\n"
			"5;Ext-One;Ext-Two=Ext-Two-Value;Ext-Three=\"Ext Three Value\"\r\n"
			"pedia\r\n"
			"E\r\n"
			" in\r\n"
			"\r\n"
			"chunks.\r\n"
			"0\r\n"
			"Post-Chunked-Body-Header-1: Value1\r\n"
			"Post-Chunked-Body-Header-2: Value2\r\n"
			"\r\n"
		};

		REQUIRE_NOTHROW( asio::write(connection,
				asio::buffer(outgoing_request)) );
	}

	// Должны прочитать положительный ответ.
	{
		std::string response;
		REQUIRE_NOTHROW(
				asio::read_until( connection, asio::dynamic_buffer(response),
						"\r\n0\r\n\r\n" ) );
		std::cout << response << std::endl;
		REQUIRE( restinio::string_algo::starts_with(
				response, "HTTP/1.1 200 OK"sv ) );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

