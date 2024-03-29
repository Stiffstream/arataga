/*!
 * @file
 * @brief SOCKS5 related connection_handlers.
 */

#include <arataga/acl_handler/connection_handler_ifaces.hpp>
#include <arataga/acl_handler/handler_factories.hpp>
#include <arataga/acl_handler/buffers.hpp>

#include <arataga/utils/overloaded.hpp>

#include <variant>

namespace arataga::acl_handler
{

namespace handlers::socks5
{

// Forward declarations of some factories.
//
// The implementation is going below.
//
[[nodiscard]]
connection_handler_shptr_t
make_username_password_auth_stage_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	first_chunk_for_next_handler_t first_chunk_data,
	std::chrono::steady_clock::time_point created_at );

[[nodiscard]]
connection_handler_shptr_t
make_no_authentification_stage_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	first_chunk_for_next_handler_t first_chunk_data,
	std::chrono::steady_clock::time_point created_at );

[[nodiscard]]
connection_handler_shptr_t
make_command_stage_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	first_chunk_for_next_handler_t first_chunk_data,
	std::optional<std::string> username,
	std::optional<std::string> password,
	std::chrono::steady_clock::time_point created_at );

[[nodiscard]]
connection_handler_shptr_t
make_connect_command_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	first_chunk_for_next_handler_t first_chunk_data,
	std::optional<std::string> username,
	std::optional<std::string> password,
	std::byte atype_value,
	byte_sequence_t dst_addr,
	std::uint16_t dst_port );

[[nodiscard]]
connection_handler_shptr_t
make_bind_command_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	first_chunk_for_next_handler_t first_chunk_data,
	std::optional<std::string> username,
	std::optional<std::string> password,
	std::byte atype_value,
	byte_sequence_t dst_addr,
	std::uint16_t dst_port );

constexpr std::byte version_byte{ 0x5u };
constexpr std::byte no_authentification_method{ 0x0u };
constexpr std::byte username_password_auth_method{ 0x2u };
constexpr std::byte no_acceptable_methods{ 0xffu };

constexpr std::byte atype_ipv4{ 0x1u };
constexpr std::byte atype_domainname{ 0x3u };
constexpr std::byte atype_ipv6{ 0x4u };

constexpr std::byte command_reply_successed{ 0x0u };
constexpr std::byte command_reply_general_server_failure{ 0x1u };
constexpr std::byte command_reply_connection_not_allowed{ 0x2u };
constexpr std::byte command_reply_host_unreachable{ 0x4u };
constexpr std::byte command_reply_command_not_supported{ 0x7u };
constexpr std::byte command_reply_atype_not_supported{ 0x8u };

//
// make_negative_command_reply
//
//! Helper function for making a negative reply to command PDU.
template< typename Buffer >
void
make_negative_command_reply(
	Buffer & buffer,
	std::byte reply_code )
{
	buffer.write_byte( version_byte );
	buffer.write_byte( reply_code );
	buffer.write_byte( std::byte{0x0} ); // RSV
	buffer.write_byte( std::byte{0x0} ); // ATYPE.
}

//
// ensure_valid_first_chunk_size
//
[[nodiscard]]
static first_chunk_t
ensure_valid_size(
	first_chunk_t first_chunk,
	std::size_t minimal_allowed_size )
{
	if( first_chunk.capacity() < minimal_allowed_size )
		throw acl_handler_ex_t{
				fmt::format( "size of the first chunk is too small: "
						"{} bytes, up to {} bytes expected",
						first_chunk.capacity(),
						minimal_allowed_size )
			};

	return first_chunk;
}

class auth_method_detection_handler_t final : public connection_handler_t
{
	//! Max size of the first PDU from a user.
	static constexpr std::size_t first_pdu_max_size =
			1 /* VER */
			+ 1 /* method count */
			+ 255 /* methods */
			;

	//! The first chunk for incoming connection.
	/*!
	 * @since v.0.5.0
	 */
	first_chunk_t m_first_chunk;

	//! Incoming buffer for parsing the first PDU.
	/*!
	 * A list of authentification methods should be here.
	 */
	in_external_buffer_t m_first_pdu;

	//! Outgoing buffer for the reply to the first PDU.
	/*
	 * Only 2 bytes in the reply.
	 */
	out_buffer_fixed_t< 2u > m_response;

	//! The timepoint when the connection was accepted.
	std::chrono::steady_clock::time_point m_created_at;

	//! The selected authentification method.
	/*!
	 * Will be empty if we don't find an appropriate method.
	 */
	std::optional< std::byte > m_accepted_method{ std::nullopt };

public:
	auth_method_detection_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		first_chunk_for_next_handler_t first_chunk_data,
		std::chrono::steady_clock::time_point created_at )
		:	connection_handler_t{ std::move(ctx), id, std::move(connection) }
		,	m_first_chunk{
					ensure_valid_size(
							first_chunk_data.giveaway_chunk(),
							first_pdu_max_size )
			}
		,	m_first_pdu{
					m_first_chunk.buffer(),
					m_first_chunk.capacity(),
					first_chunk_data.remaining_bytes()
			}
		,	m_created_at{ created_at }
	{}

protected:
	void
	on_start_impl() override
	{
		// Try to select an authentification method.
		handle_data_already_read_or_read_more();
	}

	void
	on_timer_impl() override
	{
		if( std::chrono::steady_clock::now() >= m_created_at +
				context().config().socks_handshake_phase_timeout() )
		{
			connection_remover_t remover{
					*this,
					remove_reason_t::current_operation_timed_out
			};

			using namespace arataga::utils::string_literals;
			easy_log_for_connection(
					spdlog::level::warn,
					"socks5: handshake phase timed out"_static_str );
		}
	}

public:
	arataga::utils::string_literal_t
	name() const noexcept override
	{
		using namespace arataga::utils::string_literals;
		return "socks5-auth-method-detector"_static_str;
	}

private:
	void
	handle_data_already_read_or_read_more()
	{
		if( const auto read_result = try_handle_data_read();
				data_parsing_result_t::need_more == read_result )
		{
			// Has to read more data.
			read_some(
					m_connection,
					m_first_pdu,
					[this]()
					{
						handle_data_already_read_or_read_more();
					} );
		}
	}

	[[nodiscard]]
	data_parsing_result_t
	try_handle_data_read()
	{
		// NOTE: this check is used for safety reasons.
		if( !m_first_pdu.remaining() )
			throw acl_handler_ex_t{
				"auth_method_detection_handler_t::try_handle_data_read: "
				"m_first_pdu is empty()"
			};

		buffer_read_trx_t read_trx{ m_first_pdu };

		(void)m_first_pdu.read_byte(); // Skip the version byte.

		if( m_first_pdu.remaining() > 0u )
		{
			std::size_t methods = std::to_integer< std::size_t >(
					m_first_pdu.read_byte() );
			// NOTE: it seems that some clients send auth PDU and
			// username/password PDU as a single package without
			// waiting for a responce from the proxy.
			// In that case m_first_pdu can contain more data than we need
			// at the moment.
			if( methods <= m_first_pdu.remaining() )
			{
				handle_auth_methods( methods );
				
				// All required data read even if handle_auth_methods()
				// initiated the disconnection of the client.
				read_trx.commit();

				return data_parsing_result_t::success;
			}
		}

		return data_parsing_result_t::need_more;
	}

	// NOTE: this method assumes that m_first_pdu contains enough
	// data to hold the whole list of supported by user
	// authentification methods.
	void
	handle_auth_methods(
		std::size_t methods_to_handle )
	{
		// Get the list of auth methods as byte sequence to process it
		// without touching m_first_pdu anymore.
		const auto methods_sequence = m_first_pdu.read_bytes_as_sequence(
				methods_to_handle );

		::arataga::logging::proxy_mode::trace(
				[this, methods_sequence]( auto level )
				{
					log_message_for_connection(
							level,
							fmt::format( "socks5: auth methods from client: {}",
									collect_method_ids( methods_sequence )
							)
					);
				} );

		// Prefer "username/password" method. Then "no_auth" method.
		m_accepted_method = try_find_specific_auth_method(
				username_password_auth_method, methods_sequence );
		if( !m_accepted_method )
			m_accepted_method = try_find_specific_auth_method(
					no_authentification_method, methods_sequence );

		if( m_accepted_method )
		{
			::arataga::logging::proxy_mode::trace(
					[this]( auto level )
					{
						log_message_for_connection(
								level,
								fmt::format( "socks5: auth method to be used: {:#x}",
										*m_accepted_method ) );
					} );

			m_response.write_byte( version_byte );
			m_response.write_byte( *m_accepted_method );

			write_whole(
					m_connection,
					m_response,
					[this]()
					{
						replace_handler(
								[this]() { return make_appropriate_handler(); } );
					} );
		}
		else
		{
			m_response.write_byte( version_byte );
			m_response.write_byte( no_acceptable_methods );

			write_whole(
					m_connection,
					m_response,
					[this, method_ids = collect_method_ids( methods_sequence )]()
					{
						connection_remover_t remover{
								*this,
								remove_reason_t::protocol_error
						};

						easy_log_for_connection(
								spdlog::level::err,
								format_string{
										"socks5: no supported auth methods "
										"(client methods: {})"
								},
								method_ids );
					} );
		}
	}

	[[nodiscard]]
	static std::string
	collect_method_ids(
		byte_sequence_t methods_sequence )
	{
		std::string result;

		for( const auto method : methods_sequence )
		{
			if( !result.empty() )
				result += ", ";
			result += fmt::format( "{:#x}", method );
		}

		return result;
	}

	[[nodiscard]]
	static std::optional< std::byte >
	try_find_specific_auth_method(
		const std::byte expected_method,
		byte_sequence_t methods_sequence ) noexcept
	{
		for( const auto method : methods_sequence )
		{
			if( expected_method == method )
			{
				return method;
			}
		}

		return std::nullopt;
	}

	[[nodiscard]]
	connection_handler_shptr_t
	make_appropriate_handler()
	{
		// NOTE: it seems that some clients send auth PDU and
		// username/password PDU as a single package without
		// waiting for a responce from the proxy.
		// In that case some non-processed data can remain in m_first_pdu.
		// That data has to be passed to the next connection-handler.
		auto chunk_for_next_handler = make_first_chunk_for_next_handler(
				std::move(m_first_chunk),
				m_first_pdu.read_position(),
				m_first_pdu.size() );

		if( no_authentification_method == m_accepted_method.value() )
			return make_no_authentification_stage_handler(
					m_ctx,
					m_id,
					std::move(m_connection),
					std::move(chunk_for_next_handler),
					m_created_at );
		else
		{
			return make_username_password_auth_stage_handler(
					m_ctx,
					m_id,
					std::move(m_connection),
					std::move(chunk_for_next_handler),
					m_created_at );
		}
	}
};

//
// username_password_auth_handler_t
//
class username_password_auth_handler_t final : public connection_handler_t
{
	static constexpr std::byte expected_version{ 0x1u };
	static constexpr std::byte access_denied{ 0x1u };
	static constexpr std::byte access_granted{ 0x0u };

	//! Max size of auth PDU.
	static constexpr std::size_t max_auth_pdu_size =
			1 // VER
			+ 1 // ULEN
			+ 255 // UNAME
			+ 1 // PLEN
			+ 255 // PASSWD
			;

	//! The first chunk for the incoming connection.
	/*!
	 * @since v.0.5.0
	 */
	first_chunk_t m_first_chunk;

	//! The buffer for reading a PDU with authentification data.
	/*!
	 * https://tools.ietf.org/html/rfc1929
	 */
	in_external_buffer_t m_auth_pdu;

	//! The buffer for the reply.
	out_buffer_fixed_t< 2 > m_response;

	//! The timepoint when the connection was accepted.
	std::chrono::steady_clock::time_point m_created_at;

public:
	username_password_auth_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		first_chunk_for_next_handler_t first_chunk_data,
		std::chrono::steady_clock::time_point created_at )
		:	connection_handler_t{ std::move(ctx), id, std::move(connection) }
		,	m_first_chunk{
				ensure_valid_size(
						first_chunk_data.giveaway_chunk(),
						max_auth_pdu_size )
			}
		,	m_auth_pdu{
				m_first_chunk.buffer(),
				m_first_chunk.capacity(),
				first_chunk_data.remaining_bytes()
			}
		,	m_created_at{ created_at }
	{}

protected:
	void
	on_start_impl() override
	{
		// Since v.0.3.2 we assume that some bytes from auth PDU
		// can already be in m_auth_pdu buffer.
		handle_data_already_read_or_read_more();
	}

	void
	on_timer_impl() override
	{
		if( std::chrono::steady_clock::now() >= m_created_at +
				context().config().socks_handshake_phase_timeout() )
		{
			connection_remover_t remover{
					*this,
					remove_reason_t::current_operation_timed_out
			};

			using namespace arataga::utils::string_literals;
			easy_log_for_connection(
					spdlog::level::warn,
					"socks5: handshake phase timed out"_static_str );
		}
	}

public:
	arataga::utils::string_literal_t
	name() const noexcept override
	{
		using namespace arataga::utils::string_literals;
		return "socks5-username-password-auth-handler"_static_str;
	}

private:
	void
	handle_data_already_read_or_read_more()
	{
		if( const auto read_result = try_handle_data_read();
				data_parsing_result_t::need_more == read_result )
		{
			// Has to read the next portion of data.
			read_some(
					m_connection,
					m_auth_pdu,
					[this]()
					{
						handle_data_already_read_or_read_more();
					} );
		}
	}

	[[nodiscard]]
	data_parsing_result_t
	try_handle_data_read()
	{
		// Since v.0.3.2 this method can be called when m_auth_pdu is empty.
		if( 0u == m_auth_pdu.total_size() )
			return data_parsing_result_t::need_more;

		// There are something to parse. Let's do it.
		buffer_read_trx_t read_trx{ m_auth_pdu };

		const auto version = m_auth_pdu.read_byte();
		if( expected_version != version )
		{
			connection_remover_t remover{
					*this,
					remove_reason_t::protocol_error
			};

			easy_log_for_connection(
					spdlog::level::err,
					format_string{
							"unsupported version of socks5 username/password "
							"auth PDU: {}, expected version: {}"
					},
					version, expected_version
			);

			return data_parsing_result_t::invalid_data;
		}

		if( !m_auth_pdu.remaining() )
			return data_parsing_result_t::need_more;

		const auto uname_len = std::to_integer< std::size_t >(
				m_auth_pdu.read_byte() );
		if( uname_len > m_auth_pdu.remaining() )
			return data_parsing_result_t::need_more;

		std::string username = m_auth_pdu.read_bytes_as_string( uname_len );

		if( !m_auth_pdu.remaining() )
			return data_parsing_result_t::need_more;

		const auto passwd_len = std::to_integer< std::size_t >(
				m_auth_pdu.read_byte() );
		if( passwd_len > m_auth_pdu.remaining() )
			return data_parsing_result_t::need_more;

		std::string password = m_auth_pdu.read_bytes_as_string( passwd_len );

		// NOTE: since v.0.5.0 we don't control the presence of some
		// data after auth PDU.
		// It allow some clients to send command PDU just after auth PDU
		// without waiting for a reply from the proxy.

		// All data has been read, nothing left in the buffer.
		read_trx.commit();

		// Can go to the next step.
		send_positive_response_then_replace_handler(
				std::move(username),
				std::move(password) );

		return data_parsing_result_t::success;
	}

	void
	send_positive_response_then_replace_handler(
		std::string username,
		std::string password )
	{
		m_response.write_byte( expected_version );
		m_response.write_byte( access_granted );
		write_whole(
				m_connection,
				m_response,
				[this, uname = std::move(username), passwd = std::move(password)]()
				{
					replace_handler(
							[&]()
							{
								return make_command_stage_handler(
										m_ctx,
										m_id,
										std::move(m_connection),
										make_first_chunk_for_next_handler(
												std::move(m_first_chunk),
												m_auth_pdu.read_position(),
												m_auth_pdu.size() ),
										std::move(uname),
										std::move(passwd),
										m_created_at );
							} );
				} );
	}
};

//
// no_authentification_handler_t
//
class no_authentification_handler_t final : public connection_handler_t
{
	static constexpr std::byte expected_version{ 0x1u };
	static constexpr std::byte access_granted{ 0x0u };

	//! Max size of auth PDU with empty username and password.
	/*!
	 * https://tools.ietf.org/html/rfc1929
	 */
	static constexpr std::size_t max_auth_pdu_size =
			1 // VER
			+ 1 // ULEN, has to be 0.
			+ 1 // PLEN, has to be 0.
			;

	//! The first chunk for the incoming connection.
	/*!
	 * @since v.0.5.0
	 */
	first_chunk_t m_first_chunk;

	//! The buffer for reading a PDU with authentification data.
	/*!
	 * https://tools.ietf.org/html/rfc1929
	 */
	in_external_buffer_t m_auth_pdu;

	//! Buffer for the reply.
	out_buffer_fixed_t< 2 > m_response;

	//! The timepoint when the connection was accepted.
	std::chrono::steady_clock::time_point m_created_at;

public:
	no_authentification_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		first_chunk_for_next_handler_t first_chunk_data,
		std::chrono::steady_clock::time_point created_at )
		:	connection_handler_t{ std::move(ctx), id, std::move(connection) }
		,	m_first_chunk{
				ensure_valid_size(
						first_chunk_data.giveaway_chunk(),
						max_auth_pdu_size )
			}
		,	m_auth_pdu{
				m_first_chunk.buffer(),
				m_first_chunk.capacity(),
				first_chunk_data.remaining_bytes()
			}
		,	m_created_at{ created_at }
	{}

protected:
	void
	on_start_impl() override
	{
		read_some(
				m_connection,
				m_auth_pdu,
				[this]()
				{
					handle_data_already_read_or_read_more();
				} );
	}

	void
	on_timer_impl() override
	{
		if( std::chrono::steady_clock::now() >= m_created_at +
				context().config().socks_handshake_phase_timeout() )
		{
			connection_remover_t remover{
					*this,
					remove_reason_t::current_operation_timed_out
			};

			using namespace arataga::utils::string_literals;
			easy_log_for_connection(
					spdlog::level::warn,
					"socks5: handshake phase timed out"_static_str );
		}
	}

public:
	arataga::utils::string_literal_t
	name() const noexcept override
	{
		using namespace arataga::utils::string_literals;
		return "socks5-no-authentification-handler"_static_str;
	}

private:
	void
	handle_data_already_read_or_read_more()
	{
		if( const auto read_result = try_handle_data_read();
				data_parsing_result_t::need_more == read_result )
		{
			// Has to read the next portion of data.
			read_some(
					m_connection,
					m_auth_pdu,
					[this]()
					{
						handle_data_already_read_or_read_more();
					} );
		}
	}

	[[nodiscard]]
	data_parsing_result_t
	try_handle_data_read()
	{
		// NOTE: this check is used for safety reasons.
		if( !m_auth_pdu.remaining() )
			throw acl_handler_ex_t{
				"no_authentification_handler_t::try_handle_data_read: "
				"m_auth_pdu is empty()"
			};

		buffer_read_trx_t read_trx{ m_auth_pdu };

		const auto version = m_auth_pdu.read_byte();

		// There could be a trick: curl sends auth PDU with
		// empty username/password, but Firefox doesn't send auth PDU
		// at all and sends command PDU immediately.
		//
		// So if the version number is corresponds to SOCKS5 then
		// switch to the next connection-handler right now.
		if( version_byte == version )
		{
			replace_handler(
					[this]()
					{
						return make_command_stage_handler(
								m_ctx,
								m_id,
								std::move(m_connection),
								// All data read goes to the next handler.
								make_first_chunk_for_next_handler(
										std::move(m_first_chunk),
										// No data read
										0u,
										m_auth_pdu.size() ),
								std::nullopt, // No username.
								std::nullopt, // No password.
								m_created_at );
					} );

			return data_parsing_result_t::success;
		}

		if( expected_version != version )
		{
			connection_remover_t remover{
					*this,
					remove_reason_t::protocol_error
			};

			easy_log_for_connection(
					spdlog::level::err,
					format_string{
							"unsupported version of socks5 username/password "
							"auth PDU: {}, expected version: {}"
					},
					version, expected_version
			);

			return data_parsing_result_t::invalid_data;
		}

		if( !m_auth_pdu.remaining() )
			return data_parsing_result_t::need_more;

		const auto uname_len = std::to_integer< std::size_t >(
				m_auth_pdu.read_byte() );
		if( uname_len != 0u )
		{
			connection_remover_t remover{
					*this,
					remove_reason_t::protocol_error
			};

			easy_log_for_connection(
					spdlog::level::err,
					format_string{ "expected 0 as username length, read {}" },
					uname_len
			);

			return data_parsing_result_t::invalid_data;
		}

		if( !m_auth_pdu.remaining() )
			return data_parsing_result_t::need_more;

		const auto passwd_len = std::to_integer< std::size_t >(
				m_auth_pdu.read_byte() );
		if( passwd_len != 0 )
		{
			connection_remover_t remover{
					*this,
					remove_reason_t::protocol_error
			};

			easy_log_for_connection(
					spdlog::level::err,
					format_string{ "expected 0 as password length, read {}" },
					passwd_len
			);

			return data_parsing_result_t::invalid_data;
		}

		// Everything has been read. Maybe something is present in
		// the buffer, but that data will be processed by the next handler.
		read_trx.commit();

		// Can go to the next step.
		send_positive_response_then_replace_handler();

		return data_parsing_result_t::success;
	}

	void
	send_positive_response_then_replace_handler()
	{
		m_response.write_byte( expected_version );
		m_response.write_byte( access_granted );

		write_whole(
				m_connection,
				m_response,
				[this]()
				{
					replace_handler(
							[this]()
							{
								return make_command_stage_handler(
									m_ctx,
									m_id,
									std::move(m_connection),
									make_first_chunk_for_next_handler(
											std::move(m_first_chunk),
											m_auth_pdu.read_position(),
											m_auth_pdu.size() ),
									std::nullopt,
									std::nullopt,
									m_created_at );
							} );
				} );
	}
};

//
// command_handler_t
//
class command_handler_t final : public connection_handler_t
{
	static constexpr std::byte connect_cmd{ 0x1u };
	static constexpr std::byte bind_cmd{ 0x2u };

	//! Max size for the command PDU.
	/*!
	 * https://tools.ietf.org/html/rfc1928
	 */
	static constexpr std::size_t max_command_pdu_size =
			1 // VER
			+ 1 // CMD
			+ 1 // RESERVED
			+ 1 // ATYP
			+ 256 // DST.ADDR (it's the max possible length).
			+ 2 // DST.PORT
			;

	//! The first chunk for the incoming connection.
	/*!
	 * @since v.0.5.0
	 */
	first_chunk_t m_first_chunk;

	//! Buffer for the command PDU.
	in_external_buffer_t m_command_pdu;

	//! Buffer for the negative reply.
	/*!
	 * Positive replies will be formed by handlers of specific commands.
	 */
	out_buffer_fixed_t<
			1 // VER
			+ 1 // REPLY
			+ 1 // RESERVED
			+ 1 // ATYP
		> m_negative_reply_pdu;

	//! User's name.
	/*!
	 * If empty then authentification by IP should be performed.
	 */
	std::optional<std::string> m_username;
	//! User's password.
	std::optional<std::string> m_password;

	//! The timepoint when the connection was accepted.
	std::chrono::steady_clock::time_point m_created_at;

public:
	command_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		first_chunk_for_next_handler_t first_chunk_data,
		std::optional<std::string> username,
		std::optional<std::string> password,
		std::chrono::steady_clock::time_point created_at )
		:	connection_handler_t{ std::move(ctx), id, std::move(connection) }
		,	m_first_chunk{
				ensure_valid_size(
						first_chunk_data.giveaway_chunk(),
						max_command_pdu_size )
			}
		,	m_command_pdu{
				m_first_chunk.buffer(),
				m_first_chunk.capacity(),
				first_chunk_data.remaining_bytes()
			}
		,	m_username{ std::move(username) }
		,	m_password{ std::move(password) }
		,	m_created_at{ created_at }
	{}

protected:
	void
	on_start_impl() override
	{
		read_some(
			m_connection,
			m_command_pdu,
			[this]()
			{
				handle_data_already_read_or_read_more();
			} );
	}

	void
	on_timer_impl() override
	{
		if( std::chrono::steady_clock::now() >= m_created_at +
				context().config().socks_handshake_phase_timeout() )
		{
			connection_remover_t remover{
					*this,
					remove_reason_t::current_operation_timed_out
			};

			using namespace arataga::utils::string_literals;
			easy_log_for_connection(
					spdlog::level::warn,
					"socks5_command timed out"_static_str );

			easy_log_for_connection(
					spdlog::level::warn,
					"socks5: handshake phase timed out"_static_str );
		}
	}

public:
	arataga::utils::string_literal_t
	name() const noexcept override
	{
		using namespace arataga::utils::string_literals;
		return "socks5-command-handler"_static_str;
	}

private:
	void
	handle_data_already_read_or_read_more()
	{
		if( const auto read_result = try_handle_data_read();
				data_parsing_result_t::need_more == read_result )
		{
			// Has to read the next portion of data.
			read_some(
					m_connection,
					m_command_pdu,
					[this]()
					{
						handle_data_already_read_or_read_more();
					} );
		}
	}

	[[nodiscard]]
	data_parsing_result_t
	try_handle_data_read()
	{
		// NOTE: this check is used for safety reasons.
		if( !m_command_pdu.remaining() )
			throw acl_handler_ex_t{
				"command_handler_t::try_handle_data_read: "
				"m_auth_pdu is empty()"
			};

		buffer_read_trx_t read_trx{ m_command_pdu };

		const auto version = m_command_pdu.read_byte();
		if( version_byte != version )
		{
			connection_remover_t remover{
					*this,
					remove_reason_t::protocol_error
			};

			easy_log_for_connection(
					spdlog::level::err,
					format_string{
							"unsupported version of socks5 command PDU: "
							"{}, expected version: {}"
					},
					version, version_byte
			);

			return data_parsing_result_t::invalid_data;
		}

		// At least 3 bytes have to be read:
		// CMD, RSV, ATYP.
		if( m_command_pdu.remaining() < 3u )
			return data_parsing_result_t::need_more;

		const auto cmd = m_command_pdu.read_byte();
		(void)m_command_pdu.read_byte();
		const auto atype = m_command_pdu.read_byte();

		// The content of DST.ADDR depends on atype value.
		data_parsing_result_t success_flag;
		byte_sequence_t dst_addr_bytes;
		std::tie(success_flag, dst_addr_bytes) = try_extract_dst_addr( atype );
		if( success_flag != data_parsing_result_t::success )
			return success_flag;

		// DST.PORT has to be read.
		if( m_command_pdu.remaining() < 2u )
			return data_parsing_result_t::need_more;

		std::uint16_t dst_port =
				(std::to_integer<std::uint16_t>(m_command_pdu.read_byte()) << 8u) |
				std::to_integer<std::uint16_t>(m_command_pdu.read_byte());

		// Since v.0.5.0 we don't check is there some more data
		// in the first_chunk. If there are some data that data will
		// be processed by the next handler.

		// Everything has been read, nothing left in the buffer.
		read_trx.commit();

		if( connect_cmd == cmd )
		{
			// This command has to be handled by another handler.
			// That handler will send the reply.
			replace_handler(
					[&]()
					{
						return make_connect_command_handler(
							m_ctx,
							m_id,
							std::move(m_connection),
							make_first_chunk_for_next_handler(
									std::move(m_first_chunk),
									m_command_pdu.read_position(),
									m_command_pdu.size() ),
							std::move(m_username),
							std::move(m_password),
							atype, dst_addr_bytes, dst_port );
					} );
		}
		else if( bind_cmd == cmd )
		{
			// This command has to be handled by another handler.
			// That handler will send the reply.
			replace_handler(
					[&]()
					{
						return make_bind_command_handler(
							m_ctx,
							m_id,
							std::move(m_connection),
							make_first_chunk_for_next_handler(
									std::move(m_first_chunk),
									m_command_pdu.read_position(),
									m_command_pdu.size() ),
							std::move(m_username),
							std::move(m_password),
							atype, dst_addr_bytes, dst_port );
					} );
		}
		else
		{
			// Other commands are not supported. So send the negative
			// reply right now.
			make_negative_command_reply( m_negative_reply_pdu,
					command_reply_command_not_supported );
			send_negative_reply_then_close_connection(
					remove_reason_t::protocol_error );
		}

		return data_parsing_result_t::success;
	}

	/*!
	 * @attention
	 * In the case of success a byte_sequence_t is returned.
	 * That sequence doesn't hold a copy of data, but pointed to the
	 * data inside m_command_pdu.
	 *
	 * @note
	 * This method can close the connection if some garbage is found
	 * in the PDU (like zero-length domain name).
	 */
	[[nodiscard]]
	std::tuple< data_parsing_result_t, byte_sequence_t >
	try_extract_dst_addr( std::byte atype )
	{
		if( atype_ipv4 == atype )
		{
			constexpr std::size_t addr_len = 4u;
			if( m_command_pdu.remaining() >= addr_len )
				return {
						data_parsing_result_t::success,
						m_command_pdu.read_bytes_as_sequence( addr_len )
				};
		}
		else if( atype_ipv6 == atype )
		{
			constexpr std::size_t addr_len = 16u;
			if( m_command_pdu.remaining() >= addr_len )
				return {
						data_parsing_result_t::success,
						m_command_pdu.read_bytes_as_sequence( addr_len )
				};
		}
		else if( atype_domainname == atype )
		{
			if( m_command_pdu.remaining() )
			{
				const std::size_t name_len = std::to_integer<std::size_t>(
						m_command_pdu.read_byte() );
				// Domain name can't be empty.
				if( !name_len )
				{
					connection_remover_t remover{
							*this,
							remove_reason_t::protocol_error
					};

					using namespace arataga::utils::string_literals;
					easy_log_for_connection(
							spdlog::level::warn,
							"domainname length is zero in SOCKS5 "
									"command PDU"_static_str );

					return {
							data_parsing_result_t::invalid_data,
							byte_sequence_t{}
					};
				}
				else if( m_command_pdu.remaining() >= name_len )
					return {
							data_parsing_result_t::success,
							m_command_pdu.read_bytes_as_sequence( name_len )
					};
			}
		}
		else
		{
			make_negative_command_reply(
					m_negative_reply_pdu,
					command_reply_atype_not_supported );

			send_negative_reply_then_close_connection(
					remove_reason_t::protocol_error );
		}

		return { data_parsing_result_t::need_more, byte_sequence_t{} };
	}

	void
	send_negative_reply_then_close_connection(
		remove_reason_t reason )
	{
		write_whole(
				m_connection,
				m_negative_reply_pdu,
				[this, reason]()
				{
					connection_remover_t{ *this, reason };
				} );
	}
};

//
// connect_and_bind_handler_base_t
//
/*!
 * @brief A helper base class with the functionality necessary for
 * CONNECT and BIND connection-handlers.
 */
class connect_and_bind_handler_base_t : public connection_handler_t
{
protected:
	//! The data for the next handler.
	/*!
	 * @since v.0.5.0
	 */
	first_chunk_for_next_handler_t m_first_chunk_data;

	//! Buffer for the reply.
	out_buffer_fixed_t< 
			1 // VER
			+ 1 // REP
			+ 1 // RESERVED
			+ 1 // ATYP
			+ 16 // BIND.ADDR (this is the max size for IPv6, we don't
				// use DOMAINNAME here).
			+ 2 // BIND.PORT
		> m_response;

	//! User's name.
	std::optional<std::string> m_username;
	//! User's password.
	std::optional<std::string> m_password;

	//! Type of address of the target host.
	using destination_addr_t = std::variant<
			asio::ip::address_v4,
			asio::ip::address_v6,
			std::string
		>;

	//! The target host's address.
	/*!
	 * It can be IPv4, IPv6 address or domain name in the form of a string.
	 */
	destination_addr_t m_dst_addr;
	//! The target host's port.
	std::uint16_t m_dst_port;	

	//! The target host's name.
	/*!
	 * It will play its role during the authentification/authorization.
	 */
	std::string m_target_host;

	//! The resulting address of the target host.
	/*!
	 * If the target is identified by domain name then m_target_endpoint
	 * will receive the value after DNS resolution.
	 */
	std::optional< asio::ip::tcp::endpoint > m_target_endpoint;

	//! The traffic limiter for this connection.
	/*!
	 * We get it as the result of successful authentification.
	 */
	traffic_limiter_unique_ptr_t m_traffic_limiter;

	//! The timepoint of the beginning of the current operation.
	/*!
	 * Will be used for controlling the duration of the current operation.
	 */
	std::chrono::steady_clock::time_point m_last_op_started_at;

	//! Type of method pointer that controls the duration of
	//! the current operation.
	using timeout_handler_t = void (*)(
			connect_and_bind_handler_base_t &);

	//! The pointer to the method that controls the duration of
	//! the current operation.
	timeout_handler_t m_last_op_timeout_handler{
			&connect_and_bind_handler_base_t::authentification_timeout_handler
		};

	/*!
	 * @attention
	 * The implementation assumes that dst_addr_bytes contains the
	 * valid number of bytes for IPv4 and IPv6 addresses.
	 */
	[[nodiscard]]
	static destination_addr_t
	make_destination_addr(
		std::byte atype_value,
		byte_sequence_t dst_addr_bytes )
	{
		const auto byte_to_uch = []( std::byte b ) {
				return std::to_integer<unsigned char>(b);
			};

		if( atype_ipv4 == atype_value )
		{
			asio::ip::address_v4::bytes_type raw_bytes;
			std::transform(
					dst_addr_bytes.begin(), dst_addr_bytes.end(),
					raw_bytes.begin(),
					byte_to_uch );
			return asio::ip::address_v4{ raw_bytes };
		}
		else if( atype_ipv6 == atype_value )
		{
			asio::ip::address_v6::bytes_type raw_bytes;
			std::transform(
					dst_addr_bytes.begin(), dst_addr_bytes.end(),
					raw_bytes.begin(),
					byte_to_uch );
			return asio::ip::address_v6{ raw_bytes };
		}
		else if( atype_domainname == atype_value )
		{
			return dst_addr_bytes.to_string();
		}

		throw acl_handler_ex_t{
				fmt::format( "unsupported ATYP value: {}", atype_value )
			};
	}

public:
	connect_and_bind_handler_base_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		first_chunk_for_next_handler_t first_chunk_data,
		std::optional<std::string> username,
		std::optional<std::string> password,
		std::byte atype_value,
		byte_sequence_t dst_addr,
		std::uint16_t dst_port )
		:	connection_handler_t{ std::move(ctx), id, std::move(connection) }
		,	m_first_chunk_data{ std::move(first_chunk_data) }
		,	m_username{ std::move(username) }
		,	m_password{ std::move(password) }
		,	m_dst_addr{ make_destination_addr( atype_value, dst_addr ) }
		,	m_dst_port{ dst_port }
		,	m_last_op_started_at{ std::chrono::steady_clock::now() }
	{}

protected:
	void
	on_start_impl() override
	{
		// Starting action depends on the type of dst_addr.
		std::visit( ::arataga::utils::overloaded{
			[this]( const asio::ip::address_v4 & ipv4 ) {
				try_start_with_direct_address( ipv4 );
			},
			[this]( const asio::ip::address_v6 & ipv6 ) {
				try_start_with_direct_address( ipv6 );
			},
			[this]( const std::string & hostname ) {
				// The domain name of the target host is known.
				// Store it now to be used later for authentification.
				m_target_host = hostname;

				// DNS lookup can be a long operation.
				// So we authenitificate the user first and only then
				// initiate DNS lookup (in the case of successful
				// authentification).
				initiate_authentification();
			} },
			m_dst_addr );
	}

	void
	on_timer_impl() override
	{
		(*m_last_op_timeout_handler)( *this );
	}

	//! Start a main operation after the successful authentification
	//! and DNS lookup.
	/*!
	 * Should be implemented in a derived class.
	 */
	virtual void
	initiate_next_step() = 0;

	static void
	dns_resolving_timeout_handler(
		connect_and_bind_handler_base_t & self )
	{
		if( std::chrono::steady_clock::now() >= self.m_last_op_started_at +
				self.context().config().dns_resolving_timeout() )
		{
			self.send_negative_command_reply_then_close_connection(
					remove_reason_t::current_operation_timed_out,
					spdlog::level::warn,
					"socks5: DNS-lookup timed out",
					command_reply_host_unreachable );
		}
	}

	static void
	authentification_timeout_handler(
		connect_and_bind_handler_base_t & self )
	{
		if( std::chrono::steady_clock::now() >= self.m_last_op_started_at +
				self.context().config().authentification_timeout() )
		{
			self.send_negative_command_reply_then_close_connection(
					remove_reason_t::current_operation_timed_out,
					spdlog::level::warn,
					"socks5: authentification timed out",
					command_reply_connection_not_allowed );
		}
	}

	void
	set_operation_started_markers(
		timeout_handler_t timeout_handler )
	{
		m_last_op_started_at = std::chrono::steady_clock::now();
		m_last_op_timeout_handler = timeout_handler;
	}

	void
	try_start_with_direct_address(
		asio::ip::address_v4 ipv4 )
	{
		::arataga::logging::proxy_mode::trace(
				[this, &ipv4]( auto level )
				{
					log_message_for_connection(
							level,
							fmt::format( "try_start_with_direct_address_v4: {}",
									fmt::streamed(ipv4) ) );
				} );

		// The actual target-endpoint depends on the version of ACL's
		// external IP.
		if( context().config().out_addr().is_v6() )
			m_target_endpoint = asio::ip::tcp::endpoint{
					asio::ip::make_address_v6( asio::ip::v4_mapped, ipv4 ),
					m_dst_port 
				};
		else
			m_target_endpoint = asio::ip::tcp::endpoint{ ipv4, m_dst_port };

		m_target_host = ipv4.to_string();

		initiate_authentification();
	}

	void
	try_start_with_direct_address(
		asio::ip::address_v6 ipv6 )
	{
		::arataga::logging::proxy_mode::trace(
				[this, &ipv6]( auto level )
				{
					log_message_for_connection(
							level,
							fmt::format( "try_start_with_direct_address_v6: {}",
									fmt::streamed(ipv6) ) );
				} );

		// If ACL has IPv4 external IP then we can't handle IPv6 address.
		if( context().config().out_addr().is_v4() )
		{
			send_negative_command_reply_then_close_connection(
					remove_reason_t::ip_version_mismatch,
					spdlog::level::warn,
					fmt::format( "target with IPv6 address can't be served by "
							"ACL with IPv4 out address, target_addr: {}",
							fmt::streamed(ipv6) ),
					command_reply_atype_not_supported );
		}
		else
		{
			m_target_endpoint = asio::ip::tcp::endpoint{ ipv6, m_dst_port };

			m_target_host = ipv6.to_string();

			initiate_authentification();
		}
	}

	void
	initiate_hostname_resolving(
		const std::string & hostname )
	{
		::arataga::logging::proxy_mode::trace(
				[this, &hostname]( auto level )
				{
					log_message_for_connection( level,
							fmt::format( "initiate_hostname_resolving: {}",
									hostname ) );
				} );

		set_operation_started_markers(
				&connect_and_bind_handler_base_t::dns_resolving_timeout_handler );

		context().async_resolve_hostname(
				m_id,
				hostname,
				with<const dns_resolving::hostname_result_t &>().make_handler(
					[this]( const dns_resolving::hostname_result_t & result )
					{
						on_hostname_result( result );
					} )
			);
	}

	void
	initiate_authentification()
	{
		set_operation_started_markers(
				&connect_and_bind_handler_base_t::authentification_timeout_handler );

		context().async_authentificate(
				m_id,
				authentification::request_params_t {
					// Now we are using IPv4 addresses, so don't
					// expect something else.
					m_connection.remote_endpoint().address().to_v4(),
					m_username,
					m_password,
					m_target_host,
					m_dst_port
				},
				with<authentification::result_t>().make_handler(
					[this]( authentification::result_t result )
					{
						on_authentification_result( result );
					} )
			);
	}

	void
	on_hostname_result(
		const dns_resolving::hostname_result_t & result )
	{
		std::visit( ::arataga::utils::overloaded{
				[this]
				( const dns_resolving::hostname_found_t & info )
				{
					// Now we know the destination address.
					m_target_endpoint = asio::ip::tcp::endpoint{
							info.m_ip, m_dst_port
						};

					initiate_next_step();
				},
				[this]
				( const dns_resolving::hostname_not_found_t & info )
				{
					// Domain name is not resolved.
					// We can only log that fack, send the negative reply
					// and close the connection.
					send_negative_command_reply_then_close_connection(
							remove_reason_t::unresolved_target,
							spdlog::level::warn,
							fmt::format( "DNS resolving failure: {}",
									info.m_error_desc ),
							command_reply_host_unreachable );
				}
			},
			result );
	}

	void
	on_authentification_result(
		authentification::result_t & result )
	{
		std::visit( ::arataga::utils::overloaded{
				[this]( authentification::success_t & info ) {
					m_traffic_limiter = std::move(info.m_traffic_limiter);

					// If hostname was specified then we have to do DNS lookup.
					// But if IP-address was specified then we can attempt to
					// connect.
					if( auto * hostname = std::get_if< std::string >(
							&m_dst_addr ) )
						initiate_hostname_resolving( *hostname );
					else
						initiate_next_step();
				},
				[this]( const authentification::failure_t & info ) {
					// The user has no permission to access the target host.
					// We can only log that fact, send the negative reply
					// and close the connection.
					send_negative_command_reply_then_close_connection(
							remove_reason_t::access_denied,
							spdlog::level::warn,
							fmt::format( "user is not authentificated, reason: {}",
									authentification::to_string_literal(
											info.m_reason ) ),
							command_reply_connection_not_allowed );
				}
			},
			result );
	}

	// Helper method for the simplification of procedure of
	// closing the incoming connection in the cases, when the work
	// can't be continued.
	void
	send_negative_command_reply_then_close_connection(
		remove_reason_t reason,
		spdlog::level::level_enum log_level,
		std::string_view log_message,
		std::byte reply_code )
	{
		::arataga::logging::wrap_logging(
				proxy_logging_mode,
				log_level,
				[this, log_message]( auto level )
				{
					log_message_for_connection( level, log_message );
				} );

		make_negative_command_reply( m_response, reply_code );

		write_whole(
				m_connection,
				m_response,
				[this, reason]()
				{
					connection_remover_t{ *this, reason };
				} );
	}

	template< typename Out_Buffer >
	static void
	make_positive_response_content(
		Out_Buffer & to,
		const asio::ip::tcp::endpoint & endpoint_to_report ) noexcept
	{
		// Prepare the outgoing reply.
		to.write_byte( version_byte );
		to.write_byte( command_reply_successed );
		to.write_byte( std::byte{0x0} ); // RSV
		
		const auto & address = endpoint_to_report.address();
		if( address.is_v4() )
		{
			to.write_byte( atype_ipv4 ); // ATYPE.
			to.write_bytes_from( address.to_v4().to_bytes() );
		}
		else
		{
			to.write_byte( atype_ipv6 ); // ATYPE.
			to.write_bytes_from( address.to_v6().to_bytes() );
		}
		const auto port = endpoint_to_report.port();

		to.write_byte( to_byte( port >> 8 ) );
		to.write_byte( to_byte( port & 0xffu ) );
	}

};

//
// connect_command_handler_t
//
class connect_command_handler_t final
	:	public connect_and_bind_handler_base_t
{
	//! Socket to be used for outgoing connection.
	asio::ip::tcp::socket m_out_connection;

public:
	connect_command_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		first_chunk_for_next_handler_t first_chunk_data,
		std::optional<std::string> username,
		std::optional<std::string> password,
		std::byte atype_value,
		byte_sequence_t dst_addr,
		std::uint16_t dst_port )
		:	connect_and_bind_handler_base_t{
				std::move(ctx),
				id,
				std::move(connection),
				std::move(first_chunk_data),
				std::move(username),
				std::move(password),
				atype_value,
				dst_addr,
				dst_port
			}
		// Bind the outgoing socket to the same io_context that was
		// used for incoming socket.
		,	m_out_connection{ m_connection.get_executor() }
	{}

	// This instance can be destroyed when async_connect is in progress.
	// Because of that we have to close out_connection in our
	// release() implementation.
	void
	release() noexcept override
	{
		// Ignore all errors.
		asio::error_code ec;
		m_out_connection.close( ec );

		// The furher actions will be performed by the base class.
		connect_and_bind_handler_base_t::release();
	}

	arataga::utils::string_literal_t
	name() const noexcept override
	{
		using namespace arataga::utils::string_literals;
		return "socks5-connect-command-handler"_static_str;
	}

private:
	static void
	connect_target_timeout_handler(
		connect_and_bind_handler_base_t & self )
	{
		// We can't simply access the content via a reference to the base class,
		// so just use the fact that self is pointed to
		// connect_command_handler_t.
		//
		// It this is not the case then an exception will be thrown.
		auto & this_class = dynamic_cast< connect_command_handler_t & >( self );

		if( std::chrono::steady_clock::now() >=
				this_class.m_last_op_started_at +
				this_class.context().config().connect_target_timeout() )
		{
			this_class.send_negative_command_reply_then_close_connection(
					remove_reason_t::current_operation_timed_out,
					spdlog::level::warn,
					"socks5: connect target-host timed out",
					command_reply_host_unreachable );
		}
	}

	void
	initiate_next_step() override
	{
		set_operation_started_markers(
				&connect_command_handler_t::connect_target_timeout_handler );

		try
		{
			// Expect that m_target_endpoint has a value.
			// Don't check that, but use std::optional::value() method
			// that throws an exception.
			auto & target_endpoint = m_target_endpoint.value();

			asio::error_code ec;

			m_out_connection.open( target_endpoint.protocol(), ec );
			if( ec )
			{
				send_negative_command_reply_then_close_connection(
						remove_reason_t::io_error,
						spdlog::level::err,
						fmt::format( "unable open outgoing socket: {}",
								ec.message() ),
						command_reply_general_server_failure );

				return;
			}

			// The new socket should work in non-blocking mode.
			m_out_connection.non_blocking( true, ec );
			if( ec )
			{
				send_negative_command_reply_then_close_connection(
						remove_reason_t::io_error,
						spdlog::level::err,
						fmt::format( "unable switch outgoing socket to "
								"non-blocking mode: {}",
								ec.message() ),
						command_reply_general_server_failure );

				return;
			}

			// We should use the external IP of ACL, so bind outgoing socket
			// to that IP.
			m_out_connection.bind(
					// Use 0 as port number, in that case port will be assigned
					// by the OS.
					asio::ip::tcp::endpoint{ context().config().out_addr(), 0u },
					ec );
			if( ec )
			{
				send_negative_command_reply_then_close_connection(
						remove_reason_t::io_error,
						spdlog::level::critical,
						fmt::format( "unable to bind outgoing socket to address "
								"{}: {}",
								fmt::streamed(context().config().out_addr()),
								ec.message() ),
						command_reply_general_server_failure );

				return;
			}

			::arataga::logging::proxy_mode::trace(
					[this, &target_endpoint]( auto level )
					{
						log_message_for_connection(
								level,
								fmt::format( "trying to connect {} from {}",
										fmt::streamed(target_endpoint),
										fmt::streamed(
												m_out_connection.local_endpoint()) ) );
					} );

			// Now we can initiate the connect.
			m_out_connection.async_connect(
					target_endpoint,
					with<const asio::error_code &>().make_handler(
						[this]( const asio::error_code & ec )
						{
							on_async_connect_result( ec );
						} )
				);
		}
		catch( const std::exception & x ) 
		{
			send_negative_command_reply_then_close_connection(
					remove_reason_t::unhandled_exception,
					spdlog::level::err,
					fmt::format( "an exception during the creation of "
							"outgoing connection from {} to {}: {}",
							fmt::streamed(context().config().out_addr()),
							fmt::streamed(m_target_endpoint.value()),
							x.what() ),
					command_reply_general_server_failure );
		}
	}

	void
	on_async_connect_result(
		const asio::error_code & ec )
	{
		if( ec )
		{
			// If the operation wasn't cancelled then the problem should
			// be logged and negative response has to be sent.
			if( asio::error::operation_aborted != ec )
			{
				send_negative_command_reply_then_close_connection(
						remove_reason_t::io_error,
						spdlog::level::warn,
						fmt::format( "can't connect to target host {}: {}",
								fmt::streamed(m_target_endpoint.value()),
								ec.message() ),
						command_reply_connection_not_allowed );
			}
		}
		else
		{
			::arataga::logging::proxy_mode::debug(
					[this]( auto level )
					{
						log_message_for_connection(
								level,
								fmt::format(
										"outgoing connection to {} from {} established",
										fmt::streamed(m_target_endpoint.value()),
										fmt::streamed(
												m_out_connection.local_endpoint()) ) );
					} );

			make_and_send_positive_response_then_switch_handler();
		}
	}

	void
	make_and_send_positive_response_then_switch_handler()
	{
		// Prepare the reply.
		make_positive_response_content(
				m_response, m_out_connection.local_endpoint() );

		// Now send the reply and wait for the completion...
		write_whole(
				m_connection,
				m_response,
				[this]()
				{
					// ...the response is sent, we can replace the handler.
					replace_handler(
							[this]()
							{
								return make_data_transfer_handler(
										m_ctx,
										m_id,
										std::move(m_connection),
										std::move(m_first_chunk_data),
										std::move(m_out_connection),
										std::move(m_traffic_limiter) );
							} );
				} );
	}
};

//
// bind_command_handler_t
//
class bind_command_handler_t final
	:	public connect_and_bind_handler_base_t
{
	//! The socket to be used for accepting new incoming connections.
	asio::ip::tcp::acceptor m_acceptor;

public:
	bind_command_handler_t(
		handler_context_holder_t ctx,
		handler_context_t::connection_id_t id,
		asio::ip::tcp::socket connection,
		first_chunk_for_next_handler_t first_chunk_data,
		std::optional<std::string> username,
		std::optional<std::string> password,
		std::byte atype_value,
		byte_sequence_t dst_addr,
		std::uint16_t dst_port )
		:	connect_and_bind_handler_base_t{
				std::move(ctx),
				id,
				std::move(connection),
				std::move(first_chunk_data),
				std::move(username),
				std::move(password),
				atype_value,
				dst_addr,
				dst_port
			}
		// Acceptor will be bound to the same io_context as the incoming socket.
		,	m_acceptor{ m_connection.get_executor() }
	{}

	// The instance can be removed while async_accept is in progress.
	// Therefore we have to close the acceptor manually.
	void
	release() noexcept override
	{
		// Ignore errors.
		asio::error_code ec;
		m_acceptor.close( ec );

		// The furher actions will be performed by the base class.
		connect_and_bind_handler_base_t::release();
	}

	arataga::utils::string_literal_t
	name() const noexcept override
	{
		using namespace arataga::utils::string_literals;
		return "socks5-bind-command-handler"_static_str;
	}

private:
	static void
	accept_incoming_timeout_handler(
		connect_and_bind_handler_base_t & self )
	{
		// We can't simply access the content via a reference to the base class,
		// so just use the fact that self is pointed to
		// bind_command_handler_t.
		//
		// It this is not the case then an exception will be thrown.
		auto & this_class = dynamic_cast< bind_command_handler_t & >( self );

		if( std::chrono::steady_clock::now() >=
				this_class.m_last_op_started_at +
				this_class.context().config().socks_bind_timeout() )
		{
			this_class.send_negative_command_reply_then_close_connection(
					remove_reason_t::current_operation_timed_out,
					spdlog::level::warn,
					"socks5: accepting an incoming connection timed out",
					command_reply_host_unreachable );
		}
	}

	void
	initiate_next_step() override
	{
		set_operation_started_markers(
				&bind_command_handler_t::accept_incoming_timeout_handler );

		// A helper function to reduce the amount of error-handling code.
		const auto finish_on_failure =
			[this]( std::string message ) -> void {
				send_negative_command_reply_then_close_connection(
						remove_reason_t::io_error,
						spdlog::level::err,
						message,
						command_reply_general_server_failure );
			};

		try
		{
			// The address for incoming connections.
			const asio::ip::tcp::acceptor::endpoint_type new_entry_endpoint{
					context().config().out_addr(),
					0u // Port number will be assigned by the OS.
			};

			asio::error_code ec;

			m_acceptor.open( new_entry_endpoint.protocol(), ec );
			if( ec )
			{
				return finish_on_failure(
						fmt::format( "unable make new entry point: {}",
								ec.message() ) );
			}

			m_acceptor.non_blocking( true, ec );
			if( ec )
			{
				return finish_on_failure(
						fmt::format( "unable switch outgoing socket to "
								"non-blocking mode: {}",
								ec.message() ) );
			}

			m_acceptor.set_option(
					asio::ip::tcp::acceptor::reuse_address( true ), ec );
			if( ec )
			{
				return finish_on_failure(
						fmt::format( "unable to sent REUSEADDR option: {}",
								ec.message() ) );
			}

			// An incoming connection should go to the external IP.
			// Bind our acceptor to that IP.
			m_acceptor.bind( new_entry_endpoint, ec );
			if( ec )
			{
				return finish_on_failure(
						fmt::format( "unable to bind outgoing socket to address "
								"{}: {}",
								fmt::streamed(new_entry_endpoint.address()),
								ec.message() ) );
			}

			// Wait for just one connection.
			m_acceptor.listen( 1, ec );
			if( ec )
			{
				return finish_on_failure(
						fmt::format( "call to acceptor's listen failed: {}",
								ec.message() ) );
			}

			// The user should know that we are ready.
			// New connection can be accepted after sending the reply
			// to the user.
			make_and_send_first_positive_response_then_initiate_accept();
		}
		catch( const std::exception & x ) 
		{
			send_negative_command_reply_then_close_connection(
					remove_reason_t::unhandled_exception,
					spdlog::level::err,
					fmt::format( "an exception during the creation of "
							"outgoing connection from {} to {}: {}",
							fmt::streamed(context().config().out_addr()),
							fmt::streamed(m_target_endpoint.value()),
							x.what() ),
					command_reply_general_server_failure );
		}
	}

	void
	initiate_async_accept()
	{
		::arataga::logging::proxy_mode::debug(
				[this]( auto level ) {
					log_message_for_connection(
							level,
							fmt::format( "accepting incomming connection on {}",
									fmt::streamed(m_acceptor.local_endpoint()) ) );
				} );

		m_acceptor.async_accept(
				with<const asio::error_code &, asio::ip::tcp::socket>()
				.make_handler(
					[this](
						const asio::error_code & ec,
						asio::ip::tcp::socket connection )
					{
						on_async_accept_result( ec, std::move(connection) );
					} )
			);
	}

	void
	on_async_accept_result(
		const asio::error_code & ec,
		asio::ip::tcp::socket connection )
	{
		if( ec )
		{
			// If the operation wasn't cancelled then the problem should be
			// logged and the negative response should be sent to the user.
			if( asio::error::operation_aborted != ec )
			{
				send_negative_command_reply_then_close_connection(
						remove_reason_t::io_error,
						spdlog::level::warn,
						fmt::format( "can't accept a new connection on {}: {}",
								fmt::streamed(m_acceptor.local_endpoint()),
								ec.message() ),
						command_reply_general_server_failure );
			}
		}
		else
		{
			const auto & in_connection_endpoint = connection.remote_endpoint();

			::arataga::logging::proxy_mode::trace(
					[this, &in_connection_endpoint]( auto level )
					{
						log_message_for_connection(
								level,
								fmt::format(
										"incoming connection from {} accepted on {}",
										fmt::streamed(in_connection_endpoint),
										fmt::streamed(m_acceptor.local_endpoint()) ) );
					} );

			// The new connection is expected from the address specified
			// in source BIND command.
			if( in_connection_endpoint.address() !=
					m_target_endpoint.value().address() )
			{
				// It's unexpected connection, close it.
				connection.close();

				// New accept should be initiated.
				initiate_async_accept();
			}
			else
			{
				// Normal connection accepted. Send the second reply
				// and wait a possibility to replace connection-handler.
				make_send_second_positive_response_then_switch_handler(
						in_connection_endpoint,
						std::move(connection) );
			}
		}
	}

	void
	make_and_send_first_positive_response_then_initiate_accept()
	{
		make_positive_response_content(
				m_response,
				m_acceptor.local_endpoint() );

		write_whole(
				m_connection,
				m_response,
				[this]()
				{
					// The reply is sent, now we can accept incoming connections.
					initiate_async_accept();
				} );
	}

	void
	make_send_second_positive_response_then_switch_handler(
		asio::ip::tcp::endpoint in_connection_endpoint,
		asio::ip::tcp::socket connection )
	{
		// Expect that m_response doesn't contain anything important now.
		m_response.reset();
		make_positive_response_content(
				m_response,
				in_connection_endpoint );

		write_whole(
				m_connection,
				m_response,
				[this, in_conn = std::move(connection)]() mutable
				{
					// The reply has been sent, now we can replace the handler.
					replace_handler(
							[this, &in_conn]()
							{
								return make_data_transfer_handler(
										m_ctx,
										m_id,
										std::move(m_connection),
										std::move(m_first_chunk_data),
										std::move(in_conn),
										std::move(m_traffic_limiter) );
							} );
				} );
	}
};

//
// make_username_password_auth_stage_handler
//

[[nodiscard]]
connection_handler_shptr_t
make_username_password_auth_stage_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	first_chunk_for_next_handler_t first_chunk_data,
	std::chrono::steady_clock::time_point created_at )
{
	return std::make_shared< username_password_auth_handler_t >(
			std::move(ctx),
			id,
			std::move(connection),
			std::move(first_chunk_data),
			created_at );
}

//
// make_no_authentification_stage_handler
//
[[nodiscard]]
connection_handler_shptr_t
make_no_authentification_stage_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	first_chunk_for_next_handler_t first_chunk_data,
	std::chrono::steady_clock::time_point created_at )
{
	return std::make_shared< no_authentification_handler_t >(
			std::move(ctx),
			id,
			std::move(connection),
			std::move(first_chunk_data),
			created_at );
}

//
// make_command_stage_handler
//

[[nodiscard]]
connection_handler_shptr_t
make_command_stage_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	first_chunk_for_next_handler_t first_chunk_data,
	std::optional<std::string> username,
	std::optional<std::string> password,
	std::chrono::steady_clock::time_point created_at )
{
	return std::make_shared< command_handler_t >(
			std::move(ctx),
			id,
			std::move(connection),
			std::move(first_chunk_data),
			std::move(username),
			std::move(password),
			created_at );
}

//
// make_connect_command_handler
//
[[nodiscard]]
connection_handler_shptr_t
make_connect_command_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	first_chunk_for_next_handler_t first_chunk_data,
	std::optional<std::string> username,
	std::optional<std::string> password,
	std::byte atype_value,
	byte_sequence_t dst_addr,
	std::uint16_t dst_port )
{
	return std::make_shared< connect_command_handler_t >(
			std::move(ctx),
			id,
			std::move(connection),
			std::move(first_chunk_data),
			std::move(username),
			std::move(password),
			atype_value,
			dst_addr,
			dst_port );
}

//
// make_bind_command_handler
//
[[nodiscard]]
connection_handler_shptr_t
make_bind_command_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	first_chunk_for_next_handler_t first_chunk_data,
	std::optional<std::string> username,
	std::optional<std::string> password,
	std::byte atype_value,
	byte_sequence_t dst_addr,
	std::uint16_t dst_port )
{
	return std::make_shared< bind_command_handler_t >(
			std::move(ctx),
			id,
			std::move(connection),
			std::move(first_chunk_data),
			std::move(username),
			std::move(password),
			atype_value,
			dst_addr,
			dst_port );
}

} /* namespace handlers::socks5 */

//
// make_socks5_auth_method_detection_handler
//
[[nodiscard]]
connection_handler_shptr_t
make_socks5_auth_method_detection_handler(
	handler_context_holder_t ctx,
	handler_context_t::connection_id_t id,
	asio::ip::tcp::socket connection,
	first_chunk_for_next_handler_t first_chunk_data,
	std::chrono::steady_clock::time_point created_at )
{
	using namespace handlers::socks5;

	return std::make_shared< auth_method_detection_handler_t >(
			std::move(ctx),
			id,
			std::move(connection),
			std::move(first_chunk_data),
			created_at );
}

} /* namespace arataga::acl_handler */

