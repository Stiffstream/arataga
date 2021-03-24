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

[[nodiscard]]
auto
make_shutdowner( asio::ip::tcp::endpoint target_endpoint )
{
	return [target_endpoint]() {
		asio::io_context ctx;
		asio::ip::tcp::socket client{ ctx };
		client.connect( target_endpoint );
		asio::write( client, asio::buffer( "shutdown\r\n\r\n"sv ) );
	};
}

template< typename Handler >
[[nodiscard]]
auto
make_target_handler(
	asio::ip::tcp::acceptor & acceptor,
	Handler handler )
{
	return [&acceptor, h = std::move(handler)]()
		{
			for(;;)
			{
				asio::ip::tcp::socket incoming{ acceptor.get_executor() };

				asio::error_code ec;
				acceptor.accept( incoming, ec );
				if( ec )
					return;

				std::string data;
				asio::read_until(
						incoming, asio::dynamic_buffer(data), "\r\n\r\n"sv, ec );
				if( ec )
					return;
				if( "shutdown\r\n\r\n" == data )
					return;

				h( incoming, data );
			}
		};
}

TEST_CASE("close target-end instead of response") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	asio::io_context target_context;
	const auto target_endpoint = asio::ip::tcp::endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			9090
		};
	asio::ip::tcp::acceptor acceptor{
			target_context,
			target_endpoint,
			true 
		};
	std::thread target_processing_thread{
			[&target_context, &acceptor]()
			{
				make_target_handler(
						acceptor,
						[]( asio::ip::tcp::socket & /*incoming*/,
							const std::string & )
						{ } )
				();
			}
		};

	auto target_processing_thread_joiner = so_5::details::at_scope_exit(
			[&target_processing_thread] {
				target_processing_thread.join();
			} );
	auto acceptor_closer = so_5::details::at_scope_exit(
			[&acceptor] {
				acceptor.close();
			} );
	auto target_shutdowner = so_5::details::at_scope_exit(
			make_shutdowner( target_endpoint ) );

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
			"GET http://localhost:9090/ HTTP/1.1\r\n"
			"Host: localhost:9090\r\n"
			"Proxy-Authorization: basic dXNlcjoxMjM0NQ==\r\n"
			"Content-Length: 0\r\n"
			"\r\n"
		};

		REQUIRE_NOTHROW( asio::write(connection,
				asio::buffer(outgoing_request)) );
	}

	{
		std::array< char, 512 > data;
		std::size_t bytes_read;
		REQUIRE_NOTHROW( bytes_read = connection.read_some(asio::buffer(data)) );
		std::string_view response{ &data[ 0 ], bytes_read };
//		std::cout << response << std::endl;
		REQUIRE( restinio::string_algo::starts_with(
				response, "HTTP/1.1 502 Bad Gateway"sv ) );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("partial response") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	asio::io_context target_context;
	const auto target_endpoint = asio::ip::tcp::endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			9090
		};
	asio::ip::tcp::acceptor acceptor{
			target_context,
			target_endpoint,
			true 
		};
	std::thread target_processing_thread{
			[&target_context, &acceptor]()
			{
				make_target_handler(
						acceptor,
						[]( asio::ip::tcp::socket & incoming,
							const std::string & )
						{
							asio::error_code ec;
							asio::write( incoming, asio::buffer( "HTT"sv ), ec );
						} )
				();
			}
		};

	auto target_processing_thread_joiner = so_5::details::at_scope_exit(
			[&target_processing_thread] {
				target_processing_thread.join();
			} );
	auto acceptor_closer = so_5::details::at_scope_exit(
			[&acceptor] {
				acceptor.close();
			} );
	auto target_shutdowner = so_5::details::at_scope_exit(
			make_shutdowner( target_endpoint ) );

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
			"GET http://localhost:9090/ HTTP/1.1\r\n"
			"Host: localhost:9090\r\n"
			"Proxy-Authorization: basic dXNlcjoxMjM0NQ==\r\n"
			"Content-Length: 0\r\n"
			"\r\n"
		};

		REQUIRE_NOTHROW( asio::write(connection,
				asio::buffer(outgoing_request)) );
	}

	{
		std::array< char, 512 > data;
		std::size_t bytes_read;
		REQUIRE_NOTHROW( bytes_read = connection.read_some(asio::buffer(data)) );
		std::string_view response{ &data[ 0 ], bytes_read };
//		std::cout << response << std::endl;
		REQUIRE( restinio::string_algo::starts_with(
				response, "HTTP/1.1 502 Bad Gateway"sv ) );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("close target-end after headers") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	asio::io_context target_context;
	const auto target_endpoint = asio::ip::tcp::endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			9090
		};
	asio::ip::tcp::acceptor acceptor{
			target_context,
			target_endpoint,
			true 
		};
	std::thread target_processing_thread{
			[&target_context, &acceptor]()
			{
				make_target_handler(
						acceptor,
						[]( asio::ip::tcp::socket & incoming,
							const std::string & )
						{
							asio::error_code ec;
							asio::write( incoming,
									asio::buffer(
										"HTTP/1.1 200 OK\r\n"
										"Content-Length: 25600\r\n"
										"Content-Encoding: text/plain\r\n"
										"\r\n"sv ),
									ec );
						} )
				();
			}
		};

	auto target_processing_thread_joiner = so_5::details::at_scope_exit(
			[&target_processing_thread] {
				target_processing_thread.join();
			} );
	auto acceptor_closer = so_5::details::at_scope_exit(
			[&acceptor] {
				acceptor.close();
			} );
	auto target_shutdowner = so_5::details::at_scope_exit(
			make_shutdowner( target_endpoint ) );

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
			"GET http://localhost:9090/ HTTP/1.1\r\n"
			"Host: localhost:9090\r\n"
			"Proxy-Authorization: basic dXNlcjoxMjM0NQ==\r\n"
			"Content-Length: 0\r\n"
			"\r\n"
		};

		REQUIRE_NOTHROW( asio::write(connection,
				asio::buffer(outgoing_request)) );
	}

	// Have to read until "\r\n\r\n".
	{
		std::string data;
		REQUIRE_NOTHROW(
				asio::read_until( connection,
						asio::dynamic_buffer(data),
						"\r\n\r\n" ) );
	}

	// The next read attempt should lead to EOF.
	{
		std::array< char, 16 > data;
		asio::error_code ec;
		(void)connection.read_some( asio::buffer(data), ec );
		REQUIRE( asio::error::eof == ec );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("status-line too long") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	asio::io_context target_context;
	const auto target_endpoint = asio::ip::tcp::endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			9090
		};
	asio::ip::tcp::acceptor acceptor{
			target_context,
			target_endpoint,
			true 
		};
	std::thread target_processing_thread{
			[&target_context, &acceptor]()
			{
				make_target_handler(
						acceptor,
						[]( asio::ip::tcp::socket & incoming,
							const std::string & )
						{
							asio::error_code ec;
							asio::write( incoming,
									asio::buffer(
											"HTTP/1.1 200 "
											"01234567890123456789"
											"01234567890123456789"
											"01234567890123456789"
											"01234567890123456789"
											"01234567890123456789"
											"01234567890123456789"
											"01234567890123456789"
											"01234567890123456789"
											"01234567890123456789\r\n"
											"\r\n"sv
									),
									ec );
						} )
				();
			}
		};

	auto target_processing_thread_joiner = so_5::details::at_scope_exit(
			[&target_processing_thread] {
				target_processing_thread.join();
			} );
	auto acceptor_closer = so_5::details::at_scope_exit(
			[&acceptor] {
				acceptor.close();
			} );
	auto target_shutdowner = so_5::details::at_scope_exit(
			make_shutdowner( target_endpoint ) );

	chs::handler_config_values_t config_values;
	config_values.m_http_headers_complete_timeout = 2s;
	config_values.m_http_message_limits.m_max_status_line_length = 100u;

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
			"GET http://localhost:9090/ HTTP/1.1\r\n"
			"Host: localhost:9090\r\n"
			"Proxy-Authorization: basic dXNlcjoxMjM0NQ==\r\n"
			"Content-Length: 0\r\n"
			"\r\n"
		};

		REQUIRE_NOTHROW( asio::write(connection,
				asio::buffer(outgoing_request)) );
	}

	{
		std::array< char, 512 > data;
		std::size_t bytes_read;
		REQUIRE_NOTHROW( bytes_read = connection.read_some(asio::buffer(data)) );
		std::string_view response{ &data[ 0 ], bytes_read };
//		std::cout << response << std::endl;
		REQUIRE( restinio::string_algo::starts_with(
				response, "HTTP/1.1 502 Bad Gateway"sv ) );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("http-field name too long") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	asio::io_context target_context;
	const auto target_endpoint = asio::ip::tcp::endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			9090
		};
	asio::ip::tcp::acceptor acceptor{
			target_context,
			target_endpoint,
			true 
		};
	std::thread target_processing_thread{
			[&target_context, &acceptor]()
			{
				make_target_handler(
						acceptor,
						[]( asio::ip::tcp::socket & incoming,
							const std::string & )
						{
							asio::error_code ec;
							asio::write( incoming,
									asio::buffer(
											"HTTP/1.1 200 OK\r\n"
											"Dummy-Header-101234567890123456789-"
											"Dummy-Header-201234567890123456789-"
											"Dummy-Header-301234567890123456789-"
											"Dummy-Header-401234567890123456789-"
											"Dummy-Header-501234567890123456789-"
											"Dummy-Header-601234567890123456789-"
											"Dummy-Header-701234567890123456789-"
											"Dummy-Header-801234567890123456789-"
											"Dummy-Header-9: 01234567890123456789\r\n"
											"\r\n"sv
									),
									ec );
						} )
				();
			}
		};

	auto target_processing_thread_joiner = so_5::details::at_scope_exit(
			[&target_processing_thread] {
				target_processing_thread.join();
			} );
	auto acceptor_closer = so_5::details::at_scope_exit(
			[&acceptor] {
				acceptor.close();
			} );
	auto target_shutdowner = so_5::details::at_scope_exit(
			make_shutdowner( target_endpoint ) );

	chs::handler_config_values_t config_values;
	config_values.m_http_headers_complete_timeout = 2s;
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
			"GET http://localhost:9090/ HTTP/1.1\r\n"
			"Host: localhost:9090\r\n"
			"Proxy-Authorization: basic dXNlcjoxMjM0NQ==\r\n"
			"Content-Length: 0\r\n"
			"\r\n"
		};

		REQUIRE_NOTHROW( asio::write(connection,
				asio::buffer(outgoing_request)) );
	}

	{
		std::array< char, 512 > data;
		std::size_t bytes_read;
		REQUIRE_NOTHROW( bytes_read = connection.read_some(asio::buffer(data)) );
		std::string_view response{ &data[ 0 ], bytes_read };
//		std::cout << response << std::endl;
		REQUIRE( restinio::string_algo::starts_with(
				response, "HTTP/1.1 502 Bad Gateway"sv ) );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("http-field value too long") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	asio::io_context target_context;
	const auto target_endpoint = asio::ip::tcp::endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			9090
		};
	asio::ip::tcp::acceptor acceptor{
			target_context,
			target_endpoint,
			true 
		};
	std::thread target_processing_thread{
			[&target_context, &acceptor]()
			{
				make_target_handler(
						acceptor,
						[]( asio::ip::tcp::socket & incoming,
							const std::string & )
						{
							asio::error_code ec;
							asio::write( incoming,
									asio::buffer(
											"HTTP/1.1 200 OK\r\n"
											"Dummy-Header-1: 01234567890123456789-"
											"Dummy-Header-201234567890123456789-"
											"Dummy-Header-301234567890123456789-"
											"Dummy-Header-401234567890123456789-"
											"Dummy-Header-501234567890123456789-"
											"Dummy-Header-601234567890123456789-"
											"Dummy-Header-701234567890123456789-"
											"Dummy-Header-801234567890123456789-"
											"Dummy-Header-901234567890123456789\r\n"
											"\r\n"sv
									),
									ec );
						} )
				();
			}
		};

	auto target_processing_thread_joiner = so_5::details::at_scope_exit(
			[&target_processing_thread] {
				target_processing_thread.join();
			} );
	auto acceptor_closer = so_5::details::at_scope_exit(
			[&acceptor] {
				acceptor.close();
			} );
	auto target_shutdowner = so_5::details::at_scope_exit(
			make_shutdowner( target_endpoint ) );

	chs::handler_config_values_t config_values;
	config_values.m_http_headers_complete_timeout = 2s;
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
			"Host: localhost:9090\r\n"
			"Proxy-Authorization: basic dXNlcjoxMjM0NQ==\r\n"
			"Content-Length: 0\r\n"
			"\r\n"
		};

		REQUIRE_NOTHROW( asio::write(connection,
				asio::buffer(outgoing_request)) );
	}

	{
		std::array< char, 512 > data;
		std::size_t bytes_read;
		REQUIRE_NOTHROW( bytes_read = connection.read_some(asio::buffer(data)) );
		std::string_view response{ &data[ 0 ], bytes_read };
//		std::cout << response << std::endl;
		REQUIRE( restinio::string_algo::starts_with(
				response, "HTTP/1.1 502 Bad Gateway"sv ) );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

TEST_CASE("Total http-fields size too big") {
	asio::ip::tcp::endpoint proxy_endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			2444
		};

	asio::io_context target_context;
	const auto target_endpoint = asio::ip::tcp::endpoint{
			asio::ip::make_address_v4( "127.0.0.1" ),
			9090
		};
	asio::ip::tcp::acceptor acceptor{
			target_context,
			target_endpoint,
			true 
		};
	std::thread target_processing_thread{
			[&target_context, &acceptor]()
			{
				make_target_handler(
						acceptor,
						[]( asio::ip::tcp::socket & incoming,
							const std::string & )
						{
							asio::error_code ec;
							asio::write( incoming,
									asio::buffer(
											"HTTP/1.1 200 OK\r\n"
											"Dummy-Header-1: 01234567890123456789\r\n"
											"Dummy-Header-2: 01234567890123456789\r\n"
											"Dummy-Header-3: 01234567890123456789\r\n"
											"Dummy-Header-4: 01234567890123456789\r\n"
											"Dummy-Header-5: 01234567890123456789\r\n"
											"Dummy-Header-6: 01234567890123456789\r\n"
											"Dummy-Header-7: 01234567890123456789\r\n"
											"Dummy-Header-8: 01234567890123456789\r\n"
											"Dummy-Header-9: 01234567890123456789\r\n"
											"\r\n"sv
									),
									ec );
						} )
				();
			}
		};

	auto target_processing_thread_joiner = so_5::details::at_scope_exit(
			[&target_processing_thread] {
				target_processing_thread.join();
			} );
	auto acceptor_closer = so_5::details::at_scope_exit(
			[&acceptor] {
				acceptor.close();
			} );
	auto target_shutdowner = so_5::details::at_scope_exit(
			make_shutdowner( target_endpoint ) );

	chs::handler_config_values_t config_values;
	config_values.m_http_headers_complete_timeout = 2s;
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
			"GET http://localhost:9090/ HTTP/1.1\r\n"
			"Host: localhost:9090\r\n"
			"Proxy-Authorization: basic dXNlcjoxMjM0NQ==\r\n"
			"Content-Length: 0\r\n"
			"\r\n"
		};

		REQUIRE_NOTHROW( asio::write(connection,
				asio::buffer(outgoing_request)) );
	}

	{
		std::array< char, 512 > data;
		std::size_t bytes_read;
		REQUIRE_NOTHROW( bytes_read = connection.read_some(asio::buffer(data)) );
		std::string_view response{ &data[ 0 ], bytes_read };
//		std::cout << response << std::endl;
		REQUIRE( restinio::string_algo::starts_with(
				response, "HTTP/1.1 502 Bad Gateway"sv ) );
	}

	chs::dump_trace( (std::cout << "-----\n"), simulator.get_trace() );
}

