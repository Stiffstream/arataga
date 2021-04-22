/*!
 * @file
 * @brief Agent for interaction with nameservers.
 * @since v.0.4.0
 */
#include <arataga/dns_resolver/interactor/a_nameserver_interactor.hpp>

#include <arataga/logging/wrap_logging.hpp>

#include <arataga/nothrow_block/macros.hpp>

#include <noexcept_ctcheck/pub.hpp>

#include <fmt/ostream.h>

namespace arataga::dns_resolver::interactor
{

//
// a_nameserver_interactor_t
//

a_nameserver_interactor_t::a_nameserver_interactor_t(
	context_t ctx,
	application_context_t app_ctx,
	params_t params )
	:	so_5::agent_t{ std::move(ctx) }
	,	m_app_ctx{ std::move(app_ctx) }
	,	m_params{ std::move(params) }
	// NOTE: just a hardcoded value.
	// The actual value from config will be received after
	// the subscription to config_updates_mbox.
	,	m_dns_resolving_timeout{ std::chrono::seconds{4} }
	,	m_socket{ m_params.m_io_ctx }
{
}

void
a_nameserver_interactor_t::so_define_agent()
{
	so_subscribe_self()
		.event( &a_nameserver_interactor_t::evt_lookup_request );

	so_subscribe( m_app_ctx.m_global_timer_mbox )
		.event( &a_nameserver_interactor_t::evt_one_second_timer );
}

void
a_nameserver_interactor_t::so_evt_start()
{
	// Subscription for config-updates should be made here because
	// config_updates_mbox is a retained mbox.
	so_subscribe( m_app_ctx.m_config_updates_mbox ).event(
		&a_nameserver_interactor_t::evt_updated_dns_params );

	// Now we can try to open socket for outgoing packages.
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
a_nameserver_interactor_t::so_evt_finish()
{
	m_is_finished = true;
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

	NOEXCEPT_CTCHECK_ENSURE_NOEXCEPT_STATEMENT(
		form_and_send_dns_udp_package(
				cmd->m_domain_name,
				cmd->m_ip_version,
				insertion_result.first->first,
				insertion_result.first->second )
	);
}

void
a_nameserver_interactor_t::evt_updated_dns_params(
	mhood_t< arataga::config_processor::updated_dns_params_t > msg )
{
	::arataga::logging::wrap_logging(
			direct_logging_mode,
			spdlog::level::trace,
			[&]( auto & logger, auto level )
			{
				logger.log(
						level,
						"{}: update dns params", m_params.m_name );
			} );

	m_dns_resolving_timeout = msg->m_dns_resolving_timeout;

	update_nameservers_list( msg->m_nameserver_ips );
}

void
a_nameserver_interactor_t::evt_one_second_timer(
	mhood_t< arataga::one_second_timer_t > )
{
	// NOTE: don't expect exceptions here.
	const auto now = std::chrono::steady_clock::now();

	for( auto it = m_ongoing_requests.begin();
			it != m_ongoing_requests.end(); )
	{
		if( it->second.m_start_time + m_dns_resolving_timeout < now )
		{
			// This item has to be deleted due to timeout.

			// Ignore exceptions from logger.
			ARATAGA_NOTHROW_BLOCK_BEGIN()
				ARATAGA_NOTHROW_BLOCK_STAGE(log_timeout)

				::arataga::logging::wrap_logging(
						direct_logging_mode,
						spdlog::level::debug,
						[&]( auto & logger, auto level )
						{
							logger.log(
									level,
									"{}: request timed out, "
											"id={}",
									m_params.m_name,
									it->first );
						} );
			ARATAGA_NOTHROW_BLOCK_END(JUST_IGNORE)

			ARATAGA_NOTHROW_BLOCK_BEGIN()
				ARATAGA_NOTHROW_BLOCK_STAGE(send_negative_response)

				so_5::send< lookup_response_t >(
						it->second.m_reply_to,
						failed_lookup_t{ "request timed out" },
						it->second.m_result_processor );
			ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_IGNORE)

			// Item is no more needed.
			ARATAGA_NOTHROW_BLOCK_BEGIN()
				ARATAGA_NOTHROW_BLOCK_STAGE(remove_timed_out_req_from_ongoing_requests)
				auto it_to_erase = it++; // Hope it doesn't throw.
				m_ongoing_requests.erase( it_to_erase );
			ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_IGNORE)
		}
		else
			++it;
	}
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
	ongoing_req_data_t & req_data ) noexcept
{
	try
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
	catch( const std::exception & x )
	{
		NOEXCEPT_CTCHECK_ENSURE_NOEXCEPT_STATEMENT(
			handle_dns_udp_package_sending_failure( req_id, req_data, x.what() )
		);
	}
	catch( ... )
	{
		NOEXCEPT_CTCHECK_ENSURE_NOEXCEPT_STATEMENT(
			handle_dns_udp_package_sending_failure(
					req_id, req_data, "unknown exception" )
		);
	}
}

void
a_nameserver_interactor_t::handle_dns_udp_package_sending_failure(
	const ongoing_req_id_t & req_id,
	ongoing_req_data_t & req_data,
	std::string_view failure_description ) noexcept
{
	// Ignore all exceptions related to logging.
	ARATAGA_NOTHROW_BLOCK_BEGIN()
		ARATAGA_NOTHROW_BLOCK_STAGE(log_failure_reason)

		::arataga::logging::wrap_logging(
				direct_logging_mode,
				spdlog::level::err,
				[&]( auto & logger, auto level )
				{
					logger.log(
							level,
							"{}: unable to send outgoing DNS UDP package: "
									"id={}, error={}",
							m_params.m_name,
							req_id,
							failure_description );
				} );
	ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_IGNORE)

	// Ignore all exceptions related to sending of the response.
	ARATAGA_NOTHROW_BLOCK_BEGIN()
		ARATAGA_NOTHROW_BLOCK_STAGE(send_negative_response)

		so_5::send< lookup_response_t >(
				req_data.m_reply_to,
				failed_lookup_t{ "request timed out" },
				req_data.m_result_processor );

	ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_IGNORE)
}

void
a_nameserver_interactor_t::handle_async_receive_result(
	const asio::error_code & ec,
	std::size_t bytes_transferred ) noexcept
{
	if( !ec )
	{
		// Just log exceptions and ignore them.
		ARATAGA_NOTHROW_BLOCK_BEGIN()
			ARATAGA_NOTHROW_BLOCK_STAGE(handle_incoming_pkg)

			try_handle_incoming_pkg( bytes_transferred );
		ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_IGNORE)

	}
	else
	{
		// Ignore all exceptions during logging.
		ARATAGA_NOTHROW_BLOCK_BEGIN()
			ARATAGA_NOTHROW_BLOCK_STAGE(log_async_receive_from_failure)

			::arataga::logging::wrap_logging(
					direct_logging_mode,
					spdlog::level::warn,
					[&]( auto & logger, auto level )
					{
						logger.log(
								level,
								"{}: async_receive_from failed: {}",
								m_params.m_name,
								ec );
					} );
		ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_IGNORE)
	}

	// If the agent is still working then we have to initiate next read.
	if( !m_is_finished )
		// If we can't start a new operation then it's better to abort.
		initiate_next_async_read();
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
	ARATAGA_NOTHROW_BLOCK_BEGIN()
		ARATAGA_NOTHROW_BLOCK_STAGE(log_positive_response)

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
	ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_IGNORE)

	// We should handle the response only if we know about this request.
	const auto req_id = ongoing_req_id_t{
			header.m_id, m_incoming_pkg_endpoint.address()
	};
	const auto it = m_ongoing_requests.find( req_id );
	if( it == m_ongoing_requests.end() )
		return;

	// Exceptions during the collecting IPs and sending the response
	// should be ignored.
	ARATAGA_NOTHROW_BLOCK_BEGIN()
		ARATAGA_NOTHROW_BLOCK_STAGE(parse_question_part)

		// Parse and then ignore the question.
		for( oess_2::ushort_t question_i{};
				question_i < header.m_qdcount;
				++question_i )
		{
			dns_question_t question;
			bin_stream >> question;
		}

		ARATAGA_NOTHROW_BLOCK_STAGE(parse_resource_records)

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
			ARATAGA_NOTHROW_BLOCK_STAGE(no_ips_logging)

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

			ARATAGA_NOTHROW_BLOCK_STAGE(no_ips_sending_negative_response)

			so_5::send< lookup_response_t >(
					it->second.m_reply_to,
					failed_lookup_t{ "no IPs in name server response" },
					it->second.m_result_processor );
		}
		else
		{
			ARATAGA_NOTHROW_BLOCK_STAGE(sending_positive_response)

			so_5::send< lookup_response_t >(
					it->second.m_reply_to,
					successful_lookup_t{ std::move(ips) },
					it->second.m_result_processor );
		}
	ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_IGNORE)

	// Information about that request is no more needed.
	m_ongoing_requests.erase( it );
}

void
a_nameserver_interactor_t::try_handle_negative_nameserver_response(
	dns_header_t header )
{
	ARATAGA_NOTHROW_BLOCK_BEGIN()
		ARATAGA_NOTHROW_BLOCK_STAGE(log_negative_response)

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
	ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_IGNORE)

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
	ARATAGA_NOTHROW_BLOCK_BEGIN()
		ARATAGA_NOTHROW_BLOCK_STAGE(sending_negative_response)

		so_5::send< lookup_response_t >(
				it->second.m_reply_to,
				failed_lookup_t{
					fmt::format( "negative name server reply: {}",
							rcode_values::to_string( header.rcode() ) )
				},
				it->second.m_result_processor );
	ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_IGNORE)

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

	ARATAGA_NOTHROW_BLOCK_BEGIN()
		ARATAGA_NOTHROW_BLOCK_STAGE(log_async_send_failure)

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
	ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_IGNORE)

	// A negative response has to be sent.
	// Don't expect exceptions here. But if any then it's better
	// to terminate the application.
	auto it = m_ongoing_requests.find( req_id );
	if( it != m_ongoing_requests.end() )
	{
		// There can be exceptions (like std::bad_alloc). Ignore them.
		ARATAGA_NOTHROW_BLOCK_BEGIN()
			ARATAGA_NOTHROW_BLOCK_STAGE(sending_negative_response)

			so_5::send< lookup_response_t >(
					it->second.m_reply_to,
					failed_lookup_t{
							"unable to send DNS UDP package"
					},
					it->second.m_result_processor );
		ARATAGA_NOTHROW_BLOCK_END(LOG_THEN_IGNORE)

		// Data for that request is no more needed.
		m_ongoing_requests.erase( it );
	}
}

void
a_nameserver_interactor_t::update_nameservers_list(
	config_t::nameserver_ip_container_t nameserver_ips )
{
	// Assume that nameserver_ips is a small vector. So it's cheap to
	// use simplest linear search.
	nameserver_info_container_t updated_list{ m_nservers };

	bool modified = false;

	// First pass: go thru updated_list and remove items not found
	// in nameserver_ips. If an item is found in nameserver_ips then it's
	// removed from nameserver_ips.
	{
		for( std::size_t i{}; i < updated_list.size(); )
		{
			const auto it_new = std::find(
					nameserver_ips.begin(), nameserver_ips.end(),
					updated_list[ i ].m_address );
			if( it_new != nameserver_ips.end() )
			{
				// We already know that IP.
				nameserver_ips.erase( it_new );

				++i;
			}
			else
			{
				// The current item is obsolete.
				updated_list.erase( updated_list.begin() + i );
				modified = true;
			}
		}
	}

	// Second pass: go thru the remaining items in nameserver_ips and
	// make new items in updated_list.
	for( const auto & ip : nameserver_ips )
	{
		updated_list.emplace_back( ip );
		modified = true;
	}

	if( modified )
	{
		using std::swap;
		swap( m_nservers, updated_list );

		// It's very important to reinitialize that counter.
		m_last_nserver_index = 0u;
	}
}

[[nodiscard]]
so_5::mbox_t
add_interactor_to_coop(
	so_5::coop_t & coop,
	application_context_t app_ctx,
	params_t params )
{
	return coop.make_agent< a_nameserver_interactor_t >(
			std::move(app_ctx),
			std::move(params)
		)->so_direct_mbox();
}

} /* namespace arataga::dns_resolver::interactor */

