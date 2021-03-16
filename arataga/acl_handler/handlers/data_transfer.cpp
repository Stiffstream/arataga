/*!
 * @file
 * @brief Implementation of data_transfer-handler.
 */

#include <arataga/acl_handler/connection_handler_ifaces.hpp>
#include <arataga/acl_handler/handler_factories.hpp>
#include <arataga/acl_handler/buffers.hpp>

#include <noexcept_ctcheck/pub.hpp>

namespace arataga::acl_handler
{

namespace handlers::data_transfer
{

//
// data_transfer_handler_t
//
/*!
 * @brief An implementation of connection_handler for the case,
 * when connections are established and only data-transfer
 * in both directions has to be performed.
 *
 * Since v.0.2.0 a scheme with several I/O buffers for every directions
 * is used.
 *
 * Data is read into the first buffer. Then, if bandwidth limit is not
 * exceeded, the read operation into the second buffer is initiated.
 * At the same time the data from the first buffer is written in opposite
 * direction.
 *
 * The read is suspended only if:
 *
 * - there is no more free buffers for reading a next portion. It means
 *   that data writing in opposite direction is slower than the reading
 *   of data;
 * - bandwidth limit is exceeded.
 *
 * The amount of data read from a socket influences bandwidth limit in
 * opposite direction. Thus, the count of bytes read from user-end connection
 * is taken into account for outgoing traffic to target-end direction.
 * If the data is read from target-end connection then its size is taken
 * into account for outgoing traffic to user-end connection.
 */
class data_transfer_handler_t final : public connection_handler_t
{
	//! Outgoing connection (targed-end connection).
	asio::ip::tcp::socket m_out_connection;

	//! Traffic limiter for that connection.
	traffic_limiter_unique_ptr_t m_traffic_limiter;

	//! Size of an I/O buffer.
	/*!
	 * This value is taken from the config at the creation time and
	 * hasn't been changed anymore.
	 */
	const std::size_t m_io_chunk_size;

	//! State and buffers of a single direction.
	struct direction_state_t
	{
		//! The socket for this direction.
		asio::ip::tcp::socket & m_channel;

		//! Name for this direction.
		/*!
		 * @attention
		 * Assume that this is a string-literal.
		 */
		const std::string_view m_name;

		//! A single buffer for I/O operations.
		struct io_buffer_t
		{
			//! Data read from this direction to be written to opposite direction.
			std::unique_ptr< std::byte[] > m_data_read;
			//! Count of bytes in data_read.
			/*!
			 * Gets a new value after every read operation.
			 */
			std::size_t m_data_size{ 0u };

			// The constructor allocates data_read buffer.
			io_buffer_t( std::size_t io_chunk_size )
				:	m_data_read( std::make_unique<std::byte[]>(io_chunk_size) )
			{}
		};

		//! List of buffers for I/O operations.
		std::vector< io_buffer_t > m_in_buffers;

		//! Index of buffer for the next read operation.
		std::size_t m_read_index{ 0u };
		//! Count of free buffers available for read operations.
		std::size_t m_available_for_read_buffers;

		//! Index of buffer for the next write to opposite direction.
		std::size_t m_write_index{ 0u };
		//! Count of buffers with data to be written into the opposite direction.
		std::size_t m_available_for_write_buffers{ 0u };

		//! Type of this direction for traffic_limiter.
		traffic_limiter_t::direction_t m_traffic_direction;

		//! Is this direction still alive?
		bool m_is_alive{ true };

		//! Does traffic-limit for this direction exceeded?
		bool m_is_traffic_limit_exceeded{ false };

		//! Is there an active read operation?
		bool m_active_read{ false };
		//! Is there an active write operation?
		bool m_active_write{ false };

		direction_state_t(
			asio::ip::tcp::socket & channel,
			// Assume that it is a string-literal.
			std::string_view name,
			std::size_t io_chunk_size,
			std::size_t io_chunk_count,
			traffic_limiter_t::direction_t traffic_direction )
			:	m_channel{ channel }
			,	m_name{ name }
			,	m_available_for_read_buffers{ io_chunk_count }
			,	m_traffic_direction{ traffic_direction }
		{
			// I/O buffers have to be created manually.
			m_in_buffers.reserve( m_available_for_read_buffers );
			for( std::size_t i = 0u; i != m_available_for_read_buffers; ++i )
			{
				m_in_buffers.emplace_back( io_chunk_size );
			}
		}
	};

	//! Direction from the user to the target host.
	direction_state_t m_user_end;
	//! Direction from the target host to the user.
	direction_state_t m_target_end;

	//! Time point of the last successful data read (from any direction).
	std::chrono::steady_clock::time_point m_last_read_at{
			std::chrono::steady_clock::now()
		};

	[[nodiscard]]
	static traffic_limiter_unique_ptr_t
	ensure_traffic_limiter_not_null(
		traffic_limiter_unique_ptr_t value )
	{
		if( !value )
			throw acl_handler_ex_t{
					"data_transfer_handler_t's constructor: "
					"traffic_limiter parameter can't be nullptr!"
				};

		return value;
	}

public:
	data_transfer_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket in_connection,
		asio::ip::tcp::socket out_connection,
		traffic_limiter_unique_ptr_t traffic_limiter )
		:	connection_handler_t{ std::move(ctx), id, std::move(in_connection) }
		,	m_out_connection{ std::move(out_connection) }
		,	m_traffic_limiter{
				ensure_traffic_limiter_not_null( std::move(traffic_limiter) )
			}
		,	m_io_chunk_size{ context().config().io_chunk_size() }
		,	m_user_end{
				m_connection, "user-end",
				m_io_chunk_size,
				context().config().io_chunk_count(),
				traffic_limiter_t::direction_t::from_user
			}
		,	m_target_end{
				m_out_connection, "target-end",
				m_io_chunk_size,
				context().config().io_chunk_count(),
				traffic_limiter_t::direction_t::from_target
			}
	{
	}

protected:
	void
	on_start_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
			delete_protector,
			[this]( delete_protector_t, can_throw_t can_throw ) {
				// Initiate the data read from both connection.
				// The data that is read first will be written first.
				initiate_read_user_end( can_throw );
				initiate_read_target_end( can_throw );
			} );
	}

	void
	on_timer_impl( delete_protector_t delete_protector ) override
	{
		wrap_action_and_handle_exceptions(
			delete_protector,
			[this]( delete_protector_t delete_protector, can_throw_t can_throw ) {
				// Don't expect that case but make a check for safety.
				if( !m_user_end.m_is_alive && !m_target_end.m_is_alive )
				{
					return log_and_remove_connection(
							delete_protector,
							can_throw,
							remove_reason_t::unexpected_and_unsupported_case,
							spdlog::level::warn,
							"both connections are closed" );
				}

				// Some connection is still alive. So we have to check
				// inactivity time.
				const auto now = std::chrono::steady_clock::now();

				if( m_last_read_at +
						context().config().idle_connection_timeout() < now )
				{
					return log_and_remove_connection(
							delete_protector,
							can_throw,
							remove_reason_t::no_activity_for_too_long,
							spdlog::level::warn,
							"no data read for long time" );
				}

				// If some bandwidth limit was exceeded then we have to
				// recheck that limit and initiate a new read if it's possible.
				if( m_user_end.m_is_traffic_limit_exceeded )
				{
					// It's safe to initiate a new read operation because
					// yet another check will be done inside initiate_read_*
					// methods. As the result the flag will be set into the
					// right value.
					initiate_read_user_end( can_throw );
				}
				if( m_target_end.m_is_traffic_limit_exceeded )
				{
					initiate_read_target_end( can_throw );
				}
			} );
	}

	std::string_view
	name() const noexcept override
	{
		return "data-transfer-handler";
	}

	// We have to redefine this method because we have another connection
	// and that connection should be closed explicitely.
	void
	release() noexcept override
	{
		// Ignore all errors.
		asio::error_code ec;
		m_out_connection.shutdown( asio::ip::tcp::socket::shutdown_both, ec );
		m_out_connection.close( ec );

		// Let's the base class completes the release.
		connection_handler_t::release();
	}

private:
	void
	initiate_read_user_end(
		can_throw_t can_throw )
	{
		initiate_async_read_for_direction(
				can_throw, m_user_end, m_target_end );
	}

	void
	initiate_read_target_end(
		can_throw_t can_throw )
	{
		initiate_async_read_for_direction(
				can_throw, m_target_end, m_user_end );
	}

	void
	initiate_async_read_for_direction(
		can_throw_t,
		// The direction from that data should be read.
		direction_state_t & src_dir,
		// The direction to that data should be written.
		direction_state_t & dest_dir )
	{
		// We can't start a new read operation if the current one is not
		// completed yet.
		if( src_dir.m_active_read )
			return;

		// We can't start a new read operation if there is no free buffers.
		if( !src_dir.m_available_for_read_buffers )
			return;

		// How many bytes can be read on that turn?
		const auto reserved_capacity = m_traffic_limiter->reserve_read_portion(
				src_dir.m_traffic_direction, m_io_chunk_size );

		// If reserved_capacity is 0 then the bandwidth limit is exceeded.
		src_dir.m_is_traffic_limit_exceeded = ( 0u == reserved_capacity.m_capacity );

		if( src_dir.m_is_traffic_limit_exceeded )
			// Should wait for the next turn.
			return;

		// Detect the next buffer for reading into.
		const auto selected_buffer = src_dir.m_read_index;
		src_dir.m_read_index = (src_dir.m_read_index + 1u) %
				src_dir.m_in_buffers.size();

		src_dir.m_channel.async_read_some(
				asio::buffer(
						src_dir.m_in_buffers[selected_buffer].m_data_read.get(),
						reserved_capacity.m_capacity),
				with<const asio::error_code &, std::size_t>().make_handler(
					[this, &src_dir, &dest_dir, reserved_capacity, selected_buffer](
						delete_protector_t delete_protector,
						can_throw_t can_throw,
						const asio::error_code & ec,
						std::size_t bytes )
					{
						reserved_capacity.release(
								*m_traffic_limiter,
								src_dir.m_traffic_direction,
								ec,
								bytes );

						on_read_result(
								delete_protector,
								can_throw,
								src_dir, dest_dir, selected_buffer,
								ec,
								bytes );
					} )
			);

		// There should be no exceptions!
		NOEXCEPT_CTCHECK_ENSURE_NOEXCEPT_STATEMENT(
			src_dir.m_active_read = true );
		NOEXCEPT_CTCHECK_ENSURE_NOEXCEPT_STATEMENT(
			src_dir.m_available_for_read_buffers -= 1u );
	}

	void
	initiate_async_write_for_direction(
		can_throw_t,
		// The direction to that data has to be written.
		direction_state_t & dest_dir,
		// The direction from that outgoint data has to be got.
		direction_state_t & src_dir )
	{
		// We can start a new write only if the current write completed.
		if( dest_dir.m_active_write )
			return;

		// We can start a new write only if there are buffers with
		// outgoing data.
		if( !src_dir.m_available_for_write_buffers )
			return;

		// Detect a buffer with outgoing data.
		const auto selected_buffer = src_dir.m_write_index;
		src_dir.m_write_index = (src_dir.m_write_index + 1u) %
				src_dir.m_in_buffers.size();

		const auto & buffer = src_dir.m_in_buffers[ selected_buffer ];

		// Try to write the whole content of buffer with outgoing data.
		asio::async_write(
				dest_dir.m_channel,
				asio::buffer(
						buffer.m_data_read.get(),
						buffer.m_data_size),
				with<const asio::error_code &, std::size_t>().make_handler(
					[this, &dest_dir, &src_dir, selected_buffer](
						delete_protector_t delete_protector,
						can_throw_t can_throw,
						const asio::error_code & ec,
						std::size_t bytes )
					{
						on_write_result(
								delete_protector,
								can_throw,
								dest_dir, src_dir, selected_buffer,
								ec, bytes );
					} )
			);

		// There should be no exceptions!
		NOEXCEPT_CTCHECK_ENSURE_NOEXCEPT_STATEMENT(
			dest_dir.m_active_write = true );
		NOEXCEPT_CTCHECK_ENSURE_NOEXCEPT_STATEMENT(
			src_dir.m_available_for_write_buffers -= 1u );
	}

	void
	on_read_result(
		delete_protector_t delete_protector,
		can_throw_t can_throw,
		// The direction from that data was read.
		direction_state_t & src_dir,
		// The direction to that the data has to be written.
		direction_state_t & dest_dir,
		// Index of the buffer used for read.
		std::size_t selected_buffer,
		const asio::error_code & ec,
		std::size_t bytes_transferred )
	{
		// Kept here for debugging purposes.
#if 0
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::trace,
				[&]( auto level ) {
					log_message_for_connection(
							can_throw,
							level,
							fmt::format( "on_read_result {}, selected_buffer: {}, "
									"ec: {}, bytes: {}",
									src_dir.m_name,
									selected_buffer,
									ec.message(), bytes_transferred) );
				} );
#endif

		// Regardless of the result the active read operation flag
		// has to be reset.
		src_dir.m_active_read = false;

		// If this value will be empty at the end then the service of
		// the connection should be cancelled.
		std::optional< remove_reason_t > remove_reason;

		if( ec )
		{
			src_dir.m_is_alive = false;

			if( asio::error::eof == ec )
			{
				remove_reason = remove_reason_t::normal_completion;
			}
			else if( asio::error::operation_aborted == ec )
			{
				remove_reason = remove_reason_t::current_operation_canceled;
			}
			else
			{
				// If could be I/O error. But it could also be a case 
				// when arataga shuts down, the connection is closed but
				// Asio reports an error different from operation_aborted.
				if( src_dir.m_channel.is_open() )
				{
					// It's an I/O error.
					remove_reason = remove_reason_t::io_error;

					::arataga::logging::wrap_logging(
							proxy_logging_mode,
							spdlog::level::debug,
							[this, can_throw, &src_dir, &ec]( auto level )
							{
								log_message_for_connection(
										can_throw,
										level,
										fmt::format( "error reading data from {}: {}",
												src_dir.m_name,
												ec.message() ) );
							} );
				}
				else
					remove_reason = remove_reason_t::current_operation_canceled;
			}
		}

		if( remove_reason )
		{
			// There is no sense to continue. We have to destroy ourselves.
			remove_handler( delete_protector, *remove_reason );
		}
		else
		{
			// There are no errors. We trust the value of bytes_transferred.
			src_dir.m_in_buffers[selected_buffer].m_data_size = bytes_transferred;

			// Yet another buffer is available for writting.
			src_dir.m_available_for_write_buffers += 1u;

			// Should store the time of the last activity.
			m_last_read_at = std::chrono::steady_clock::now();

			// Now the data read can be sent to the opposite direction.
			initiate_async_write_for_direction( can_throw, dest_dir, src_dir );

			// We can try to start a new read operation.
			initiate_async_read_for_direction( can_throw, src_dir, dest_dir );
		}
	}

	void
	on_write_result(
		delete_protector_t delete_protector,
		can_throw_t can_throw,
		// The direction to that data was written.
		direction_state_t & dest_dir,
		// The direction from that the outgoing data was taken.
		direction_state_t & src_dir,
		// Index of buffer with outgoing data.
		std::size_t selected_buffer,
		const asio::error_code & ec,
		std::size_t bytes_transferred )
	{
		// Kept here for debugging purposes.
#if 0
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				spdlog::level::trace,
				[&]( auto level ) {
					log_message_for_connection(
							can_throw,
							level,
							fmt::format( "on_write_result {}, selected_buffer: {}, "
									"ec: {}, bytes: {}",
									dest_dir.m_name,
									selected_buffer,
									ec.message(), bytes_transferred) );
				} );
#endif

		// Regardless of the result the active write operation flag
		// has to be reset.
		dest_dir.m_active_write = false;

		// In the case of an error the work has to be cancelled.
		if( ec )
		{
			log_and_remove_connection_on_io_error(
					delete_protector,
					can_throw, ec,
					fmt::format( "writting to {}", dest_dir.m_name ) );
		}
		else
		{
			// We expect that bytes_transferred is equal to
			// src_dit.m_data_size. But if those values are different
			// the we can't continue.
			const auto expected_data_size =
					src_dir.m_in_buffers[selected_buffer].m_data_size;
			if( expected_data_size != bytes_transferred )
			{
				log_and_remove_connection(
						delete_protector,
						can_throw,
						remove_reason_t::io_error,
						spdlog::level::critical,
						fmt::format( "unexpected write result: {} data_size {} != "
								"bytes_transferred {}",
								dest_dir.m_name,
								expected_data_size,
								bytes_transferred ) );
			}
			else
			{
				// There is one more free buffer for next read.
				src_dir.m_available_for_read_buffers += 1u;

				// Becase yet another buffer is free now we can try to start
				// a new read operation.
				initiate_async_read_for_direction( can_throw, src_dir, dest_dir );

				// Maybe there are some waiting outgoing data so try to start
				// a new write operation.
				initiate_async_write_for_direction( can_throw, dest_dir, src_dir );
			}
		}
	}
};

} /* namespace handlers::data_transfer */

//
// make_data_transfer_handler
//
[[nodiscard]]
connection_handler_shptr_t
make_data_transfer_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket in_connection,
	asio::ip::tcp::socket out_connection,
	traffic_limiter_unique_ptr_t traffic_limiter )
{
	using namespace handlers::data_transfer;

	return std::make_shared< data_transfer_handler_t >(
			std::move(ctx), id,
			std::move(in_connection),
			std::move(out_connection),
			std::move(traffic_limiter) );
}

} /* namespace arataga::acl_handler */

