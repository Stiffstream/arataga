/*!
 * @file
 * @brief Implementation of connect_method_handler.
 */

#include <arataga/acl_handler/handlers/http/basics.hpp>
#include <arataga/acl_handler/handlers/http/factories.hpp>
#include <arataga/acl_handler/handlers/http/helpers.hpp>
#include <arataga/acl_handler/handlers/http/responses.hpp>

#include <arataga/acl_handler/handler_factories.hpp>

namespace arataga::acl_handler
{

namespace handlers::http
{

//
// connect_method_handler_t
//
/*!
 * @brief Connection-handler that services CONNECT method.
 */
class connect_method_handler_t final : public handler_with_out_connection_t
{
	//! The first chunk of the incoming connection.
	/*!
	 * Has to be passed to data_transfer_handler.
	 *
	 * @since v.0.5.0
	 */
	first_chunk_for_next_handler_t m_first_chunk_data;

	//! Description of the target host.
	/*!
	 * It's necessary for logging purposes.
	 */
	const std::string m_connection_target;

	//! Traffic limiter for the user.
	traffic_limiter_unique_ptr_t m_traffic_limiter;

	//! Buffer for positive response to the user.
	/*!
	 * After the sending of the response a data-transfer handler will
	 * be used for the connection.
	 */
	out_string_view_buffer_t m_positive_response;

	//! Timepoint when this object was created.
	/*!
	 * Used for controlling the timeout of sending the response.
	 */
	std::chrono::steady_clock::time_point m_created_at;

public:
	connect_method_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket in_connection,
		http_handling_state_unique_ptr_t http_state,
		request_info_t request_info,
		traffic_limiter_unique_ptr_t traffic_limiter,
		asio::ip::tcp::socket out_connection )
		:	handler_with_out_connection_t{
				std::move(ctx),
				id,
				std::move(in_connection),
				std::move(out_connection)
			}
		,	m_first_chunk_data{
				http_state->giveaway_first_chunk_for_next_handler()
			}
		,	m_connection_target{
				fmt::format( "{}:{}",
					request_info.m_target_host,
					request_info.m_target_port )
			}
		,	m_traffic_limiter{ std::move(traffic_limiter) }
		,	m_positive_response{ response_ok_for_connect_method }
		,	m_created_at{ std::chrono::steady_clock::now() }
	{
	}

protected:
	void
	on_start_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
			delete_protector,
			[this]( delete_protector_t, can_throw_t can_throw ) {
				::arataga::logging::proxy_mode::info(
						[this, can_throw]( auto level )
						{
							log_message_for_connection(
									can_throw,
									level,
									"serving-request=CONNECT " + m_connection_target );
						} );

				// Have to send positive response to the user.
				write_whole( can_throw,
						m_connection,
						m_positive_response,
						[this]( delete_protector_t delete_protector,
							can_throw_t can_throw )
						{
							// The response is sent. Now we can switch
							// to data-transfer-handler.
							replace_handler(
									delete_protector,
									can_throw,
									[this]( can_throw_t )
									{
										return make_data_transfer_handler(
												std::move(m_ctx),
												m_id,
												std::move(m_connection),
												std::move(m_first_chunk_data),
												std::move(m_out_connection),
												std::move(m_traffic_limiter) );
									} );
						} );
			} );
	}

	void
	on_timer_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
			delete_protector,
			[this]( delete_protector_t delete_protector, can_throw_t can_throw )
			{
				// Will use idle_connection_timeout as the timeout duration.
				const auto now = std::chrono::steady_clock::now();
				if( m_created_at +
						context().config().idle_connection_timeout() < now )
				{
					connection_remover_t remover{
							*this,
							delete_protector,
							remove_reason_t::no_activity_for_too_long
					};

					using namespace arataga::utils::string_literals;
					return easy_log_for_connection(
							can_throw,
							spdlog::level::warn,
							"timeout writing positive response to "
									"CONNECT method"_static_str );
				}
			} );
	}

public:
	arataga::utils::string_literal_t
	name() const noexcept override
	{
		using namespace arataga::utils::string_literals;
		return "http-connect-method-handler"_static_str;
	}
};

//
// make_connect_method_handler
//
[[nodiscard]]
connection_handler_shptr_t
make_connect_method_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket in_connection,
	http_handling_state_unique_ptr_t http_state,
	request_info_t request_info,
	traffic_limiter_unique_ptr_t traffic_limiter,
	asio::ip::tcp::socket out_connection )
{
	return std::make_shared< connect_method_handler_t >(
			std::move(ctx),
			id,
			std::move(in_connection),
			std::move(http_state),
			std::move(request_info),
			std::move(traffic_limiter),
			std::move(out_connection) );
}

} /* namespace arataga::acl_handler */

} /* namespace handlers::http */

