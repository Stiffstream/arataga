/*!
 * @file
 * @brief Implementation of negative_response_sender.
 */

#include <arataga/acl_handler/handlers/http/basics.hpp>

namespace arataga::acl_handler
{

namespace handlers::http
{

//
// negative_response_sender_handler_t
//
/*!
 * @brief Implementation of connection_handler that only sends
 * a negative response and then closes the connection.
 */
class negative_response_send_handler_t : public connection_handler_t
{
	//! Timepoint when the handler was created.
	const std::chrono::steady_clock::time_point m_created_at;

	//! Why the connection is being closed.
	const remove_reason_t m_remove_reason;

	//! Buffer to be used for the response.
	/*!
	 * We're using the fact that all negative responses are
	 * represented as string literals.
	 */
	out_string_view_buffer_t m_negative_response_buffer;

public:
	negative_response_send_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		remove_reason_t remove_reason,
		arataga::utils::string_literal_t negative_response )
		:	connection_handler_t{ std::move(ctx), id, std::move(connection) }
		,	m_created_at{ std::chrono::steady_clock::now() }
		,	m_remove_reason{ remove_reason }
		,	m_negative_response_buffer{ negative_response }
	{
	}

protected:
	void
	on_start_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
				delete_protector,
				[&]( delete_protector_t, can_throw_t can_throw )
				{
					write_whole(
							can_throw,
							m_connection,
							m_negative_response_buffer,
							[this](
								delete_protector_t delete_protector,
								can_throw_t /*can_throw*/ )
							{
								connection_remover_t{
										*this,
										delete_protector,
										m_remove_reason
									};
							} );
				} );
	}

	void
	on_timer_impl( delete_protector_t delete_protector ) override
	{
		if( std::chrono::steady_clock::now() >= m_created_at +
				context().config().http_negative_response_timeout() )
		{
			wrap_action_and_handle_exceptions(
				delete_protector,
				[this]( delete_protector_t delete_protector, can_throw_t can_throw )
				{
					connection_remover_t remover{
							*this,
							delete_protector,
							remove_reason_t::current_operation_timed_out
					};

					::arataga::logging::proxy_mode::warn(
							[this, can_throw]( auto level )
							{
								log_message_for_connection(
										can_throw,
										level,
										"http_negative_response timed out" );
							} );
				} );
		}
	}

public:
	arataga::utils::string_literal_t
	name() const noexcept override
	{
		using namespace arataga::utils::string_literals;
		return "http-negative-response-send-handler"_static_str;
	}
};

//
// make_negative_response_sender
//
[[nodiscard]]
connection_handler_shptr_t
make_negative_response_sender(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	remove_reason_t remove_reason,
	arataga::utils::string_literal_t negative_response )
{
	return std::make_shared< negative_response_send_handler_t >(
			std::move(ctx),
			id,
			std::move(connection),
			remove_reason,
			negative_response );
}

} /* namespace arataga::acl_handler */

} /* namespace handlers::http */

