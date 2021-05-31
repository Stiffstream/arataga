/*!
 * @file
 * @brief Implementation of data_transfer-handler.
 */

#include <arataga/acl_handler/connection_handler_ifaces.hpp>
#include <arataga/acl_handler/handler_factories.hpp>
#include <arataga/acl_handler/buffers.hpp>

#include <arataga/utils/overloaded.hpp>

#include <noexcept_ctcheck/pub.hpp>

namespace arataga::acl_handler
{

namespace handlers::data_transfer
{

using namespace arataga::utils::string_literals;

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
 *
 * Since v.0.5.0 data_transfer_handler_t handles the case when
 * some data is already read from the incoming connection (in the form
 * of first_chunk_for_next_handler_t object passed to the constructor).
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
	 *
	 * Since v.0.5.0 this value is obtained from first_chunk_t instance,
	 * not from the current configuration.
	 */
	const std::size_t m_io_chunk_size;

	//! State and buffers of a single direction.
	struct direction_state_t
	{
		//! The socket for this direction.
		asio::ip::tcp::socket & m_channel;

		//! Name for this direction.
		const arataga::utils::string_literal_t m_name;

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

			// The constructor for the case when data_read buffer is
			// already allocated. And can have some initial data inside.
			io_buffer_t(
				std::unique_ptr< std::byte[] > data_read,
				std::size_t data_size )
				:	m_data_read{ std::move(data_read) }
				,	m_data_size{ data_size }
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

		//! Constructor for user-end connection.
		/*!
		 * There is first_chunk, so the first item in m_in_buffers should
		 * be constructed from that first_chunk.
		 *
		 * There could also be some incoming data in the first_chunk.
		 * In that case value of m_available_for_read_buffers should be
		 * decremented, m_available_for_write_buffers should be incremented,
		 * and m_read_index should be changed appropriately.
		 *
		 * @since v.0.5.0
		 */
		direction_state_t(
			asio::ip::tcp::socket & channel,
			arataga::utils::string_literal_t name,
			first_chunk_for_next_handler_t first_chunk_data,
			std::size_t io_chunk_size,
			std::size_t io_chunk_count,
			traffic_limiter_t::direction_t traffic_direction )
			:	m_channel{ channel }
			,	m_name{ name }
			,	m_available_for_read_buffers{ io_chunk_count }
			,	m_traffic_direction{ traffic_direction }
		{
			if( first_chunk_data.chunk().capacity() != io_chunk_size )
				throw acl_handler_ex_t{
					fmt::format( "data_transfer_handler_t::direction_state_t: "
							"io_chunk_size ({}) != first_chunk.capacity ({})",
							io_chunk_size,
							first_chunk_data.chunk().capacity() )
				};

			// I/O buffers have to be created manually except the first one.
			m_in_buffers.reserve( m_available_for_read_buffers );

			// Item with index 0 has to be constructed from first_chunk.
			m_in_buffers.emplace_back(
					first_chunk_data.giveaway_chunk().giveaway_buffer(),
					first_chunk_data.remaining_bytes() );

			for( std::size_t i = 1u; i < m_available_for_read_buffers; ++i )
			{
				m_in_buffers.emplace_back( io_chunk_size );
			}

			// If there are some incoming data from the user-end then
			// it should be reflected in values of m_available_for_read_buffers,
			// m_available_for_write_buffers, m_read_index.
			if( first_chunk_data.remaining_bytes() )
			{
				m_in_buffers[ 0u ].m_data_size = first_chunk_data.remaining_bytes();
				m_available_for_read_buffers -= 1u;
				m_available_for_write_buffers += 1u;

				increment_read_index();
			}
		}

		//! Constructor for target-end connection.
		/*!
		 * There is no already read data from that direction, all buffers
		 * will be empty.
		 */
		direction_state_t(
			asio::ip::tcp::socket & channel,
			arataga::utils::string_literal_t name,
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

		void
		increment_read_index() noexcept
		{
			m_read_index = (m_read_index + 1u) % m_in_buffers.size();
		}

		void
		increment_write_index() noexcept
		{
			m_write_index = (m_write_index + 1u) % m_in_buffers.size();
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
		first_chunk_for_next_handler_t first_chunk_data,
		asio::ip::tcp::socket out_connection,
		traffic_limiter_unique_ptr_t traffic_limiter )
		:	connection_handler_t{ std::move(ctx), id, std::move(in_connection) }
		,	m_out_connection{ std::move(out_connection) }
		,	m_traffic_limiter{
				ensure_traffic_limiter_not_null( std::move(traffic_limiter) )
			}
		,	m_io_chunk_size{ first_chunk_data.chunk().capacity() }
		,	m_user_end{
				m_connection, "user-end"_static_str,
				std::move(first_chunk_data),
				m_io_chunk_size,
				context().config().io_chunk_count(),
				traffic_limiter_t::direction_t::from_user
			}
		,	m_target_end{
				m_out_connection, "target-end"_static_str,
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
				// If there are some data already read from m_user_end
				// then this data has to be written.
				if( m_user_end.m_available_for_write_buffers )
				{
					initiate_async_write_for_direction(
							can_throw,
							m_target_end,
							m_user_end );
				}

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
					connection_remover_t remover{
							*this,
							delete_protector,
							remove_reason_t::unexpected_and_unsupported_case
					};

					using namespace arataga::utils::string_literals;
					return easy_log_for_connection(
							can_throw,
							spdlog::level::warn,
							"both connections are closed"_static_str );
				}

				// Some connection is still alive. So we have to check
				// inactivity time.
				const auto now = std::chrono::steady_clock::now();

				if( m_last_read_at +
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
							"no data read for long time"_static_str );
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

	arataga::utils::string_literal_t
	name() const noexcept override
	{
		using namespace arataga::utils::string_literals;
		return "data-transfer-handler"_static_str;
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
		// This shouldn't happen. But do that check for safety.
		if( !src_dir.m_is_alive )
			return;

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
		src_dir.increment_read_index();

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
		// This shouldn't happen. But do that check for safety.
		if( !dest_dir.m_is_alive )
			return;

		// We can start a new write only if the current write completed.
		if( dest_dir.m_active_write )
			return;

		// We can start a new write only if there are buffers with
		// outgoing data.
		if( !src_dir.m_available_for_write_buffers )
			return;

		// Detect a buffer with outgoing data.
		const auto selected_buffer = src_dir.m_write_index;
		src_dir.increment_write_index();

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

	// Type that tells that the connection-handler should be removed
	// because of I/O error on read operation.
	struct handler_should_be_removed_t
	{
		remove_reason_t m_remove_reason;
	};

	// Helper types those play role of boolean flags but provide
	// additional type-safety.
	enum class can_read_src_dir_t { yes, no };
	enum class can_write_dest_dir_t { yes, no };

	// Type that tells that the connection-handler should continue its
	// work after the completion of read operation.
	struct work_should_be_continued_t
	{
		can_read_src_dir_t m_can_read_src_dir;
		can_write_dest_dir_t m_can_write_dest_dir;
	};

	// Type for representation the result of read-operation result
	// analysis.
	using read_error_code_handling_result_t = std::variant<
			handler_should_be_removed_t,
			work_should_be_continued_t
		>;

	read_error_code_handling_result_t
	handle_read_error_code(
		can_throw_t can_throw,
		direction_state_t & src_dir,
		const direction_state_t & dest_dir,
		// Index of buffer used for the reading.
		std::size_t selected_buffer,
		const asio::error_code & ec,
		std::size_t bytes_transferred )
	{
		if( !ec )
		{
			// No errors, we can trust bytes_transferred value.
			src_dir.m_in_buffers[selected_buffer].m_data_size = bytes_transferred;

			// There is another buffer with outgoing data.
			src_dir.m_available_for_write_buffers += 1u;

			// There is yet anoter activity in the channels.
			m_last_read_at = std::chrono::steady_clock::now();

			// We can read more, and we can write some more data.
			return work_should_be_continued_t{
					can_read_src_dir_t::yes,
					can_write_dest_dir_t::yes
			};
		}

		// Handle an error here.

		// src_dir is assumed to be closed regardless of error type.
		src_dir.m_is_alive = false;

		// Since v.0.2.0 several buffers are used for reading data.
		// We can find ourselves in the case when the source direction
		// is closed on the remote site, but there still are some
		// buffers with previously read data, and that data hasn't
		// written to opposite direction yet.
		if( asio::error::eof == ec )
		{
			// The src_dir is closed on remote site. We can continue
			// only if there is some pending outgoing data.
			// And if the dest_dir is still alive.
			if( dest_dir.m_is_alive
					&& 0u != src_dir.m_available_for_write_buffers )
			{
				// We can't read src_dir anymore.
				// But can write into dest_dir.
				return work_should_be_continued_t{
						can_read_src_dir_t::no,
						can_write_dest_dir_t::yes
				};
			}
			else
			{
				// There is no sense to continue.
				return handler_should_be_removed_t{
						remove_reason_t::normal_completion
				};
			}
		}
		else if( asio::error::operation_aborted == ec ||
				// There could be a case when we closed socket but
				// Asio reports an error different from
				// operation_aborted.
				!src_dir.m_channel.is_open() )
		{
			return handler_should_be_removed_t{
					remove_reason_t::current_operation_canceled
			};
		}

		// If we are here then some I/O error happened. Log it.
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

		return handler_should_be_removed_t{ remove_reason_t::io_error };
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

		// Handle the result of read operation...
		const auto handling_result = handle_read_error_code(
				can_throw,
				src_dir,
				dest_dir,
				selected_buffer,
				ec,
				bytes_transferred );
		// ...our further actions depends on that result.
		std::visit( ::arataga::utils::overloaded{
				[&]( const handler_should_be_removed_t & r ) {
					// There is no sense to continue.
					connection_remover_t{
							*this,
							delete_protector,
							r.m_remove_reason
					};
				},
				[&]( const work_should_be_continued_t & r ) {
					if( can_write_dest_dir_t::yes == r.m_can_write_dest_dir )
					{
						initiate_async_write_for_direction(
								can_throw, dest_dir, src_dir );
					}
					if( can_read_src_dir_t::yes == r.m_can_read_src_dir )
					{
						initiate_async_read_for_direction(
								can_throw, src_dir, dest_dir );
					}
				} },
				handling_result );
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
			connection_remover_t remover{
					*this,
					delete_protector,
					remove_reason_t::io_error
			};

			log_on_io_error(
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
				connection_remover_t remover{
						*this,
						delete_protector,
						remove_reason_t::io_error
				};
						
				easy_log_for_connection(
						can_throw,
						spdlog::level::critical,
						format_string{
								"unexpected write result: {} data_size {} != "
								"bytes_transferred {}"
						},
						dest_dir.m_name,
						expected_data_size,
						bytes_transferred );
			}
			else
			{
				// There is one more free buffer for next read.
				src_dir.m_available_for_read_buffers += 1u;

				bool has_outgoing_data = 
						0u != src_dir.m_available_for_write_buffers;

				// We can find outselves in the case where the source direction
				// is still alive and we can read some more data from it.
				if( src_dir.m_is_alive )
				{
					// Because we've written some data to dest_dir we
					// can now initiate a new read from src_dir.
					initiate_async_read_for_direction(
							can_throw, src_dir, dest_dir );

				}
				else
				{
					// The source direction is closed.
					// If we don't have any pending outgoing data then
					// the connection-handler has to be removed.
					if( !has_outgoing_data )
					{
						connection_remover_t remover{
								*this,
								delete_protector,
								remove_reason_t::normal_completion
						};

						easy_log_for_connection(
								can_throw,
								spdlog::level::trace,
								format_string{
										"no more outgoing data for: {}, "
										"opposite direction is closed: {}"
								},
								dest_dir.m_name,
								src_dir.m_name );
					}
				}

				// There is some pending outgoing data, we should write it.
				if( has_outgoing_data )
				{
					initiate_async_write_for_direction(
							can_throw, dest_dir, src_dir );
				}
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
	first_chunk_for_next_handler_t first_chunk,
	asio::ip::tcp::socket out_connection,
	traffic_limiter_unique_ptr_t traffic_limiter )
{
	using namespace handlers::data_transfer;

	return std::make_shared< data_transfer_handler_t >(
			std::move(ctx), id,
			std::move(in_connection),
			std::move(first_chunk),
			std::move(out_connection),
			std::move(traffic_limiter) );
}

} /* namespace arataga::acl_handler */

