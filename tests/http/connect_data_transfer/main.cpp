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

TEST_CASE("serie of large blocks") {
	constexpr std::size_t blocks_count = 200u;
	constexpr std::size_t block_size = 16384u;

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

			std::array< char, block_size > data;
			for( std::size_t i = 0u; i != block_size; )
			{
				for( char c = '0'; c <= '9' && i != block_size; ++c, ++i )
					data[ i ] = c;
			}

			for( std::size_t i = 0u; i != blocks_count; ++i )
			{
				asio::write( incoming, asio::buffer( data ), ec );

				if( ec )
				{
					std::cerr << "write data failed: " << ec << std::endl;
					break;
				}
			}

			incoming.shutdown( asio::ip::tcp::socket::shutdown_both, ec );
			incoming.close( ec );
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
	config_values.m_io_chunk_size = block_size;
	config_values.m_io_chunk_count = 6u;

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
			"CONNECT localhost:9090 HTTP/1.1\r\n"
			"Host: localhost:9090\r\n"
			"Proxy-Authorization: basic dXNlcjoxMjM0NQ==\r\n"
			"\r\n"
		};

		REQUIRE_NOTHROW( asio::write(connection,
				asio::buffer(outgoing_request)) );
	}

	// Должны прочитать положительный ответ.
	{
		std::string first_resp_part;
		REQUIRE_NOTHROW(
				asio::read_until(
						connection,
						asio::dynamic_buffer(first_resp_part),
						"HTTP/1.1 200 Ok\r\n\r\n" ) );
	}

	// Должны прочитать то, что нам отсылает удаленная сторона.
	{
		std::array< char, block_size > data;
		std::size_t i = 0u;
		for(;; ++i )
		{
			std::this_thread::sleep_for( 25ms );
			asio::error_code ec;
			asio::read( connection, asio::buffer(data), ec );
			if( ec )
				break;
		}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );

		REQUIRE( blocks_count == i );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

