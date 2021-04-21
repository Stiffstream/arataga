/*!
 * @file
 * @brief Agent for interaction with nameservers.
 * @since v.0.4.0
 */
#include <arataga/dns_resolver/interactor/a_nameserver_interactor.hpp>

#include <arataga/logging/wrap_logging.hpp>

#include <fmt/ostream.h>

namespace arataga::dns_resolver::interactor
{

//
// a_nameserver_interactor_t
//

a_nameserver_interactor_t::a_nameserver_interactor_t(
	context_t ctx,
	params_t params )
	:	so_5::agent_t{ std::move(ctx) }
	,	m_params{ std::move(params) }
	,	m_socket{ m_params.m_io_ctx }
{
//FIXME: only for testing!
m_nservers.push_back( asio::ip::make_address( "8.8.8.8" ) );
}

void
a_nameserver_interactor_t::so_define_agent()
{
	so_subscribe_self().event(
			&a_nameserver_interactor_t::evt_lookup_request );
}

void
a_nameserver_interactor_t::so_evt_start()
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::trace,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: opening UDP socket", m_params.m_name );
			} );

	m_socket.open( asio::ip::udp::v4() );
	initiate_next_async_read();

	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::info,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: started", m_params.m_name );
			} );
}

void
a_nameserver_interactor_t::evt_lookup_request(
	mhood_t< lookup_request_t > cmd )
{
	auto * nsrv_to_use = detect_nsrv_for_new_request();
	if( !nsrv_to_use )
	{
		// List of name servers is empty. We can handle that request.
		so_5::send< lookup_response_t >(
				cmd->m_reply_to,
				failed_lookup_t{ "no name servers to use" },
				cmd->m_result_processor );

		return;
	}

	// Assume that it will be a unique ID for the request.
	const auto req_id = ++(nsrv_to_use->m_req_id_counter);
	const auto insertion_result = m_ongoing_requests.try_emplace(
			ongoing_req_id_t{ req_id, nsrv_to_use->m_address },
			cmd->m_reply_to,
			cmd->m_result_processor );
	if( !insertion_result.second )
	{
		// ID is not unqiue. The request can't be handled.
		so_5::send< lookup_response_t >(
				cmd->m_reply_to,
				failed_lookup_t{
					"unable to make unique ID for request to name server"
				},
				cmd->m_result_processor );

		return;
	}

//FIXME: exceptions should be caught and handled here.
	form_and_send_dns_udp_package(
			cmd->m_domain_name,
			cmd->m_ip_version,
			insertion_result.first->first,
			insertion_result.first->second );
}

nameserver_info_t *
a_nameserver_interactor_t::detect_nsrv_for_new_request() noexcept
{
	if( m_nservers.empty() )
		return nullptr;

	m_last_nserver_index = (m_last_nserver_index + 1u) % m_nservers.size();

	return &m_nservers[ m_last_nserver_index ];
}

void
a_nameserver_interactor_t::initiate_next_async_read()
{
	m_socket.async_receive_from(
			asio::buffer( m_incoming_pkg ),
			m_incoming_pkg_endpoint,
			[self = so_5::make_agent_ref(this)]
			( const asio::error_code & ec, std::size_t bytes_transferred ) {
				self->handle_async_receive_result( ec, bytes_transferred );
			} );
}

void
a_nameserver_interactor_t::form_and_send_dns_udp_package(
	const std::string_view domain_name,
	ip_version_t ip_version,
	const ongoing_req_id_t & req_id,
	ongoing_req_data_t & req_data )
{
	oess_2::io::ofixed_mem_buf_t bin_stream{
			req_data.m_outgoing_package.data(),
			req_data.m_outgoing_package.size()
	};

	// Form the header.
	{
		dns_header_t header{ req_id.m_id, true };
		header.set_qr( dns_header_t::REQUEST );
		header.m_qdcount = 1u;

		bin_stream << header;
	}

	switch( ip_version )
	{
	case ip_version_t::ip_v4:
		// For IPv4 ask for A record.
		bin_stream << dns_question_t{
					domain_name, qtype_values::A, qclass_values::IN
			};
	break;

	case ip_version_t::ip_v6:
		// For IPv6 ask for AAAA record.
		bin_stream << dns_question_t{
				domain_name, qtype_values::AAAA, qclass_values::IN
			};
	break;
	}

	const auto bin_size = bin_stream.size();

	// Now we can send a request to name server.
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::trace,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: sending DNS UDP package, id={}, bytes={}",
						m_params.m_name,
						req_id,
						bin_size );
			} );

	m_socket.async_send_to(
			asio::buffer( req_data.m_outgoing_package.data(), bin_size ),
			asio::ip::udp::endpoint{ req_id.m_address, 53u },
			[self = so_5::make_agent_ref(this), id = req_id]
			( const asio::error_code & ec, std::size_t bytes_transferred ) {
				self->handle_async_send_result( id, ec, bytes_transferred );
			} );
}

void
a_nameserver_interactor_t::handle_async_receive_result(
	const asio::error_code & ec,
	std::size_t bytes_transferred ) noexcept
{
	if( !ec )
	{
		// Just log exceptions and ignore them.
		try
		{
			try_handle_incoming_pkg( bytes_transferred );
		}
		catch( const std::exception & x )
		{
			// Ignore all exceptions during logging.
			try
			{
				::arataga::logging::wrap_logging(
						direct_logging_mode,
						spdlog::level::err,
						[&]( auto & logger, auto level )
						{
							logger.log(
									level,
									"{}: unable to handle incoming DNS UDP package: {}",
									m_params.m_name,
									x.what() );
						} );
			}
			catch( ... ) {}
		}
		catch( ... )
		{}

		// If we can't start a new operation then it's better to abort.
		initiate_next_async_read();
	}
//FIXME: for debugging purposes only.
else
{
std::cout << "async_receive_from failure: " << ec << std::endl;
}

}

void
a_nameserver_interactor_t::try_handle_incoming_pkg(
	std::size_t bytes_transferred )
{
	std::string_view all_bin_data{
			m_incoming_pkg.data(), bytes_transferred
	};

	oess_2::io::ifixed_mem_buf_t bin_stream{
			m_incoming_pkg.data(), bytes_transferred
	};

	dns_header_t header;
	bin_stream >> header;

	if( rcode_values::ok == header.rcode() )
		try_handle_positive_nameserver_response(
				all_bin_data,
				bin_stream,
				header );
	else
		try_handle_negative_nameserver_response(
				header );
}

void
a_nameserver_interactor_t::try_handle_positive_nameserver_response(
	std::string_view all_bin_data,
	oess_2::io::istream_t & bin_stream,
	dns_header_t header )
{
	// Ignore any exceptions related to logging.
	try
	{
		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::trace,
				[&]( auto & logger, auto level )
				{
					logger.log(
							level,
							"{}: positive name server response, address={}, "
									"id={}, answer_count={}",
							m_params.m_name,
							m_incoming_pkg_endpoint.address(),
							header.m_id,
							header.m_ancount );
				} );
	}
	catch( ... ) {}

	// We should handle the response only if we know about this request.
	const auto req_id = ongoing_req_id_t{
			header.m_id, m_incoming_pkg_endpoint.address()
	};
	const auto it = m_ongoing_requests.find( req_id );
	if( it == m_ongoing_requests.end() )
		return;

	// Exceptions during the collecting IPs and sending the response
	// should be ignored.
	try
	{
		// Parse and then ignore the question.
		for( oess_2::ushort_t question_i{};
				question_i < header.m_qdcount;
				++question_i )
		{
			dns_question_t question;
			bin_stream >> question;
		}

		// Parse and process resource records.
		successful_lookup_t::address_container_t ips;
		for( oess_2::ushort_t answer_i{};
				answer_i < header.m_ancount;
				++answer_i )
		{
			dns_resource_record_t rr;
			bin_stream >> from_memory( all_bin_data, rr );

			if( qtype_values::A == rr.m_type ||
					qtype_values::AAAA == rr.m_type )
			{
				ips.push_back( asio::ip::make_address( rr.m_resource_data ) );
			}
		}

		if( ips.empty() )
		{
			// No IPs. We can only send negative response.
			::arataga::logging::wrap_logging(
					direct_logging_mode,
					spdlog::level::warn,
					[&]( auto & logger, auto level )
					{
						logger.log(
								level,
								"{}: no IPs in positive name server response, id={}",
								m_params.m_name,
								req_id );
					} );

			so_5::send< lookup_response_t >(
					it->second.m_reply_to,
					failed_lookup_t{ "no IPs in name server response" },
					it->second.m_result_processor );
		}
		else
		{
			so_5::send< lookup_response_t >(
					it->second.m_reply_to,
					successful_lookup_t{ std::move(ips) },
					it->second.m_result_processor );
		}
	}
	catch( ... ) {}

	// Information about that request is no more needed.
	m_ongoing_requests.erase( it );
}

void
a_nameserver_interactor_t::try_handle_negative_nameserver_response(
	dns_header_t header )
{
	// Ignore any exceptions related to logging.
	try
	{
		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::debug,
				[&]( auto & logger, auto level )
				{
					logger.log(
							level,
							"{}: negative name server response, address={}, "
									"id={}, error={}",
							m_params.m_name,
							m_incoming_pkg_endpoint.address(),
							header.m_id,
							rcode_values::to_string( header.rcode() ) );
				} );
	}
	catch( ... ) {}

	// If there is info for that request then we should complete it.
	const auto req_id = ongoing_req_id_t{
			header.m_id, m_incoming_pkg_endpoint.address()
	};
	const auto it = m_ongoing_requests.find( req_id );
	if( it == m_ongoing_requests.end() )
		// We don't known about that ID. Just ignore it.
		return;

	// Now `it` is a valid iterator.
	// Ignore exceptions related to sending the response.
	try
	{
		so_5::send< lookup_response_t >(
				it->second.m_reply_to,
				failed_lookup_t{
					fmt::format( "negative name server reply: {}",
							rcode_values::to_string( header.rcode() ) )
				},
				it->second.m_result_processor );
	}
	catch( ... ) {}

	// Information about that request is no more needed.
	m_ongoing_requests.erase( it );
}

void
a_nameserver_interactor_t::handle_async_send_result(
	ongoing_req_id_t req_id,
	const asio::error_code & ec,
	std::size_t /*bytes_transferred*/ ) noexcept
{
	if( !ec )
		// No errors. Nothing to do.
		return;

	// Ignore exceptions here.
	try
	{
		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::err,
				[&]( auto & logger, auto level )
				{
					logger.log(
							level,
							"{}: DNS UDP package send failure, id={}, error={}",
							m_params.m_name,
							req_id,
							ec );
				} );
	}
	catch( ... ) {}

	// A negative response has to be sent.
	// Don't expect exceptions here. But if any then it's better
	// to terminate the application.
	auto it = m_ongoing_requests.find( req_id );
	if( it != m_ongoing_requests.end() )
	{
		// There can be exceptions (like std::bad_alloc). Ignore them.
		try
		{
			so_5::send< lookup_response_t >(
					it->second.m_reply_to,
					failed_lookup_t{
							"unable to send DNS UDP package"
					},
					it->second.m_result_processor );
		}
		catch( ... ) {}

		// Data for that request is no more needed.
		m_ongoing_requests.erase( it );
	}
}

[[nodiscard]]
so_5::mbox_t
add_interactor_to_coop(
	so_5::coop_t & coop,
	params_t params )
{
	return coop.make_agent< a_nameserver_interactor_t >(
			std::move(params)
		)->so_direct_mbox();
}

} /* namespace arataga::dns_resolver::interactor */

