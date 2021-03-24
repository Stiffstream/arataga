/*!
 * @file
 * @brief connection_handler for the detection of user protocol.
 */

#include <arataga/acl_handler/connection_handler_ifaces.hpp>
#include <arataga/acl_handler/buffers.hpp>
#include <arataga/acl_handler/handler_factories.hpp>

#include <arataga/utils/overloaded.hpp>

namespace arataga::acl_handler
{

namespace handlers::protocol_detection
{

class handler_t : public connection_handler_t
{
	//! A time when the connection was accepted.
	std::chrono::steady_clock::time_point m_created_at;

	//! The buffer for the first portion of data.
	in_buffer_fixed_t< 512 > m_in_buffer;

public :
	handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection )
		:	connection_handler_t{ std::move(ctx), id, std::move(connection) }
		,	m_created_at{ std::chrono::steady_clock::now() }
	{}

protected:
	void
	on_start_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
			delete_protector,
			[this]( delete_protector_t, can_throw_t can_throw ) {
				// A new connection has to be reflected in the stats.
				context().stats_inc_connection_count( connection_type_t::generic );

				// The first part of data has to be read and analyzed.
				read_some(
						can_throw,
						m_connection,
						m_in_buffer,
						[this]( delete_protector_t delete_protector,
							can_throw_t can_throw )
						{
							analyze_data_read( delete_protector, can_throw );
						} );
			} );
	}

	void
	on_timer_impl( delete_protector_t delete_protector ) override
	{
		if( std::chrono::steady_clock::now() >= m_created_at +
				context().config().protocol_detection_timeout() )
		{
			wrap_action_and_handle_exceptions(
				delete_protector,
				[this](
					delete_protector_t delete_protector,
					can_throw_t can_throw )
				{
					log_and_remove_connection(
							delete_protector,
							can_throw,
							remove_reason_t::current_operation_timed_out,
							spdlog::level::warn,
							"protocol-detection timed out" );
				} );
		}
	}

public:
	std::string_view
	name() const noexcept override
	{
		return "protocol-detector";
	}

private:
	struct unknown_protocol_t {};

	struct connection_accepted_t
	{
		connection_type_t m_connection_type;
		connection_handler_shptr_t m_handler;
	};

	// Type to be used as the result on try_accept_*_connection methods.
	using detection_result_t = std::variant<
			unknown_protocol_t,
			connection_accepted_t
		>;

	void
	analyze_data_read(
		delete_protector_t delete_protector,
		can_throw_t can_throw )
	{
		detection_result_t detection_result{ unknown_protocol_t{} };

		// Run only those try_accept_*_connection that enabled for the ACL.
		const auto acl_protocol = context().config().acl_protocol();
		if( acl_protocol_t::autodetect == acl_protocol )
		{
			detection_result = try_accept_socks_connection( can_throw );
			if( std::holds_alternative< unknown_protocol_t >( detection_result ) )
			{
				detection_result = try_accept_http_connection( can_throw );
			}
		}
		else if( acl_protocol_t::socks == acl_protocol )
		{
			detection_result = try_accept_socks_connection( can_throw );
		}
		else if( acl_protocol_t::http == acl_protocol )
		{
			detection_result = try_accept_http_connection( can_throw );
		}

		// Analyze the result of acception attempt.
		std::visit( ::arataga::utils::overloaded{
				[this, delete_protector, can_throw]
				( connection_accepted_t & accepted )
				{
					// Update the stats. It should be done now because
					// in the case of HTTP keep-alive connection can be used.
					// In the case of HTTP keep-alive the connection should be
					// counted only once. If we'll update the stats in
					// http::initial_http_handler then the stats will be updated
					// for every incoming request (there could be many
					// requests in a single keep-alive connection).
					context().stats_inc_connection_count(
							accepted.m_connection_type );

					// The handler can be changed now.
					replace_handler(
							delete_protector,
							can_throw,
							[&]( can_throw_t ) {
								return std::move(accepted.m_handler);
							} );
				},
				[this, delete_protector, can_throw]
				( const unknown_protocol_t & )
				{
					// We don't know the protocol, the connection has to be closed.
					log_and_remove_connection(
							delete_protector,
							can_throw,
							remove_reason_t::unsupported_protocol,
							spdlog::level::warn,
							"unsupported protocol in the connection" );
				} },
				detection_result );
	}

	detection_result_t
	try_accept_socks_connection( can_throw_t /*can_throw*/ )
	{
		constexpr std::byte socks5_protocol_first_byte{ 5u };

		buffer_read_trx_t read_trx{ m_in_buffer };

		if( socks5_protocol_first_byte == m_in_buffer.read_byte() )
		{
			// Assume that is SOCKS5.
			return {
					connection_accepted_t{
							connection_type_t::socks5,
							make_socks5_auth_method_detection_handler(
									m_ctx,
									m_id,
									std::move(m_connection),
									m_in_buffer.whole_data_as_sequence(),
									m_created_at )
					}
			};
		}

		return { unknown_protocol_t{} };
	}

	detection_result_t
	try_accept_http_connection( can_throw_t can_throw )
	{
		(void)can_throw;

		buffer_read_trx_t read_trx{ m_in_buffer };

		// Assume that this is HTTP if the first byte is a capital
		// latin letter (it is because methods in HTTP are identified
		// by capital letters).
		//
		// Even if we've made a mistake the consequent parsing of HTTP
		// will fail and the connection will be closed.
		//
		const auto first_byte = m_in_buffer.read_byte();
		if( std::byte{'A'} <= first_byte && first_byte <= std::byte{'Z'} )
		{
			// Assume that it's HTTP protocol.
			return {
					connection_accepted_t{
							connection_type_t::http,
							make_http_handler(
									m_ctx,
									m_id,
									std::move(m_connection),
									m_in_buffer.whole_data_as_sequence(),
									m_created_at )
					}
			};
		}

		return { unknown_protocol_t{} };
	}
};

} /* namespace handlers::protocol_detection */

[[nodiscard]]
connection_handler_shptr_t
make_protocol_detection_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection )
{
	using namespace handlers::protocol_detection;

	return std::make_shared< handler_t >(
			std::move(ctx), id, std::move(connection) );
}

} /* namespace arataga::acl_handler */

