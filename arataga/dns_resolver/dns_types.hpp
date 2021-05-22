/*!
 * @file
 * @brief Various tools for working with DNS-related data.
 * @since v.0.4.0
 */
#pragma once

#include <arataga/utils/string_literal.hpp>
#include <arataga/utils/overloaded.hpp>

#include <oess_2/defs/h/types.hpp>
#include <oess_2/io/h/stream.hpp>
#include <oess_2/io/h/fixed_mem_buf.hpp>

#include <fmt/format.h>

#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <iosfwd>
#include <iostream>
#include <string_view>
#include <variant>

namespace arataga::dns_resolver {

namespace rcode_values {

	inline constexpr unsigned int ok = 0;
	inline constexpr unsigned int format_error = 1;
	inline constexpr unsigned int server_failure = 2;
	inline constexpr unsigned int name_error = 3;
	inline constexpr unsigned int not_implemented = 4;
	inline constexpr unsigned int refused = 5;

	[[nodiscard]]
	inline arataga::utils::string_literal_t
	to_string( unsigned int rcode ) noexcept
	{
		using namespace arataga::utils::string_literals;

		switch( rcode )
		{
		case ok: return "ok"_static_str;
		case format_error: return "format error"_static_str;
		case server_failure: return "server failure"_static_str;
		case name_error: return "name error"_static_str;
		case not_implemented: return "not implemented"_static_str;
		case refused: return "refused"_static_str;
		}

		return "unknown error code"_static_str;
	}

} /* namespace rcode_values */

//
// dns_header_t
//

/*!
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

*/
struct dns_header_t
{
	enum
	{
		REQUEST = 0,
		RESPONSE = 1
	};

	dns_header_t() noexcept
	{}

	dns_header_t( oess_2::ushort_t id, bool recursive = true ) noexcept
		: m_id{ id }
	{
		set_rd( recursive );
	}

	oess_2::ushort_t m_id{};
	oess_2::ushort_t m_flags{};
	oess_2::ushort_t m_qdcount{};
	oess_2::ushort_t m_ancount{};
	oess_2::ushort_t m_nscount{};
	oess_2::ushort_t m_arcount{};

	oess_2::io::istream_t &
	read_from( oess_2::io::istream_t & i )
	{
		i
			>> m_id
			>> m_flags
			>> m_qdcount
			>> m_ancount
			>> m_nscount
			>> m_arcount;

		return i;
	}

	oess_2::io::ostream_t &
	write_to( oess_2::io::ostream_t & o ) const
	{
		o
			<< m_id
			<< m_flags
			<< m_qdcount
			<< m_ancount
			<< m_nscount
			<< m_arcount;

		return o;
	}

	std::ostream &
	dump_flags( std::ostream & o ) const
	{
		o
			<<"{ "
			<< "qr: " << qr() << "; "
			<< "opcode: " << opcode() << "; "
			<< "aa: " << aa() << "; "
			<< "tc: " << tc() << "; "
			<< "rd: " << rd() << "; "
			<< "ra: " << ra() << "; "
			<< "z: " << z() << "; "
			<< "rcode: " << rcode()
			<<" }";

		return o;
	}

	std::ostream &
	dump_to( std::ostream & o ) const
	{
		o
			<<"{ "
			<< "id: " << m_id << "; "
			<< "flags: ";

		dump_flags(o) << "; "
			<< "qdcount: " << m_qdcount << "; "
			<< "ancount: " << m_ancount << "; "
			<< "nscount: " << m_nscount << "; "
			<< "arcount: " << m_arcount
			<<" }";

		return o;
	}

	void
	set_qr( int qr ) noexcept
	{
		if( qr == RESPONSE )
			m_flags |= 0x8000;
		else
			m_flags &= ~(0x8000);
	}

	[[nodiscard]]
	int
	qr() const noexcept
	{
		return m_flags & 0x8000? RESPONSE: REQUEST;
	}

	[[nodiscard]]
	unsigned int
	opcode() const noexcept
	{
		return m_flags & 0x7800;
	}

	[[nodiscard]]
	bool
	aa() const noexcept
	{
		return m_flags & 0x400;
	}

	[[nodiscard]]
	bool
	tc() const noexcept
	{
		return m_flags & 0x200;
	}

	void
	set_rd( bool val ) noexcept
	{
		val? m_flags |= 0x100: m_flags &= ~(0x100);
	}

	[[nodiscard]]
	bool
	rd() const noexcept
	{
		return m_flags & 0x100;
	}

	[[nodiscard]]
	bool
	ra() const noexcept
	{
		return m_flags & 0x80;
	}

	[[nodiscard]]
	unsigned int
	z() const noexcept
	{
		return m_flags & 0x70;
	}

	[[nodiscard]]
	unsigned int
	rcode() const noexcept
	{
		return m_flags & 0xF;
	}
};

inline oess_2::io::istream_t &
operator >> ( oess_2::io::istream_t & i, dns_header_t & h )
{
	return h.read_from( i );
}

inline oess_2::io::ostream_t &
operator << ( oess_2::io::ostream_t & o, const dns_header_t & h )
{
	return h.write_to( o );
}

inline std::ostream &
operator << ( std::ostream & o, const dns_header_t & h )
{
	return h.dump_to( o );
}

//! Helper class for converting resource name in human-readable
//! form like www.google.ru into internal representation like 3www6google2ru0.
/*!
 * Receives a name in human-readable format (like `www.google.ru`).
 * Translates that name into 3www6google2ru0 in the constructor. Hold the
 * translated value.
 */
class dns_format_name_t
{
public :
	// The maximum allowed length.
	// See: https://blogs.msdn.microsoft.com/oldnewthing/20120412-00/?p=7873
	static constexpr std::size_t max_length = 254u;
	static constexpr std::size_t max_label_length = 63;

	struct already_translated_value_t
	{
		std::string m_value;
	};

	dns_format_name_t()
		:	dns_format_name_t( std::string{} )
	{}

	dns_format_name_t( std::string_view value )
		:	m_value( translate( value ) )
	{}

	dns_format_name_t( already_translated_value_t v ) noexcept
		:	m_value( std::move(v.m_value) )
	{}

	[[nodiscard]]
	const std::string &
	raw_value() const noexcept
	{
		return m_value;
	}

	std::ostream &
	dump_to( std::ostream & o ) const
	{
		std::size_t i{};
		const auto get_next_label_size = [&]() -> std::size_t {
			return static_cast<unsigned char>(m_value[i]);
		};

		for( auto label_size = get_next_label_size();
				0u != label_size;
				label_size = get_next_label_size() )
		{
			o << std::string_view( &m_value[i+1u], label_size ) << ".";
			i += 1u + label_size;
		}

		return o;
	}

	[[nodiscard]]
	friend bool
	operator==(
		const dns_format_name_t & a,
		const dns_format_name_t & b ) noexcept
	{
		return a.raw_value() == b.raw_value();
	}

	[[nodiscard]]
	friend bool
	operator!=(
		const dns_format_name_t & a,
		const dns_format_name_t & b ) noexcept
	{
		return a.raw_value() != b.raw_value();
	}

	friend void
	swap( dns_format_name_t & a, dns_format_name_t & b ) noexcept
	{
		a.m_value.swap( b.m_value );
	}

	static void
	ensure_valid_length( std::string_view v )
	{
		if( v.size() > max_length )
			throw std::invalid_argument{ "dns_format_name_t: length too long" };
	}

private :
	std::string m_value;

	[[nodiscard]]
	std::string
	translate( std::string_view src )
	{
		ensure_valid_length( src );

		// If src is empty then src_end_index will be 0.
		// If src is "www." then src_end_index will be 3 (skip the ending '.').
		// If src is "www" then src_end_index will be 3 (assume that
		// the ending '.' is just skipped).
		const std::size_t src_end_index = src.empty() ? 0u :
			( '.' == *src.rbegin() ? src.size() - 1u : src.size() );

		std::string result;
		result.reserve( src_end_index + 1u /* the final 0 */ );

		// Because the trailing dot (if present) is already skipped,
		// we don't expect values like "www.yandex.ru." or "www...".
		// Only values in format "www.yandex.ru" or "www".
		// It means that every dot found should open a non-empty label.
		bool expects_next_label = false;

		// If src is empty then we don't enter into that loop at all.
		for( std::size_t i{}; i < src_end_index; )
		{
			// Position where the actual length should be stored.
			const auto label_size_index = result.size();
			std::size_t label_size = 0;
			result += '\0';

			bool dot_found = false;
			for(; i < src_end_index && !dot_found; ++i )
			{
				// Internal loop should be finished if '.' is found.
				if( '.' == src[i] )
				{
					dot_found = true;
				}
				else
				{
					result += src[i];
					++label_size;
				}
			}

			// The current label finished. Check its validity.
			if( 0 == label_size )
				throw std::invalid_argument{ "empty label is found" };
			if( max_label_length < label_size )
				throw std::invalid_argument{
						fmt::format( "too long label is found, length={}",
								label_size )
				};

			// We ensure that the value of label_size will fit into char.
			result[ label_size_index ] = static_cast< char >( label_size );

			// Expects next non-empty label only if dot was found.
			expects_next_label = dot_found;
		}

		if( expects_next_label )
			throw std::invalid_argument{ "empty label is found" };

		result += '\0';

		return result;
	}
};

/*!
 * Helpers for loading DNS-names from a stream of from binary PDU
 * already loaded into the memory.
 */
namespace dns_format_name_tools
{

//FIXME: this class should be replaced by std::variant.
struct name_terminator_t {};

struct name_length_t
{
	oess_2::uchar_t m_length;
};

struct reference_offset_t
{
	oess_2::ushort_t m_offset;
};

//! The result of extraction length byte.
/*!
 * The result can be one of:
 *
 * - the length of the name;
 * - the offset for the reference;
 * - name terminator.
 */
using load_size_byte_result_t = std::variant<
		name_terminator_t,
		name_length_t,
		reference_offset_t
	>;

[[nodiscard]]
inline load_size_byte_result_t
load_size_byte( oess_2::io::istream_t & i )
{
	oess_2::uchar_t size_byte;
	i >> size_byte;

	// If two most significant bits are set then it is a reference
	// to the place where a name is located.
	if( size_byte & 0xC0 )
	{
		oess_2::uchar_t second_offset_byte;
		i >> second_offset_byte;

		return reference_offset_t{
				static_cast<oess_2::ushort_t>(
						((static_cast< oess_2::ushort_t >( size_byte ) & 0x3Fu) << 8)
						+second_offset_byte
				)
		};
	}
	else if( size_byte == '\0' )
		return name_terminator_t{};
	else
		return name_length_t{ size_byte };
}

inline void
load_next_label(
	oess_2::io::istream_t & from,
	std::size_t label_size,
	std::string & to )
{
	if( label_size )
	{
		const auto old_size = to.size();
		// Make the result string big enough and the load all the content
		// by a single read operation.
		to.resize( old_size + label_size + 1 /* the length byte */ );
		to[ old_size ] = static_cast<char>(label_size);
		from.read( &to[ old_size+1 ], label_size );
	}
}

void
read_from_memory_buffer_impl(
	unsigned int references_recursion_deep,
	std::string_view all_buffer,
	oess_2::io::istream_t & stream,
	std::string & to );

inline void
read_reference_from_memory_buffer_impl(
	// Deep of reference recursion.
	unsigned int references_recursion_deep,
	// This should be a buffer that starts with DNS-header.
	std::string_view all_buffer,
	size_t offset,
	std::string & to )
{
	oess_2::io::ifixed_mem_buf_t ibuf( all_buffer.data(), all_buffer.size() );

	ibuf.shift_bytes( offset );

	read_from_memory_buffer_impl(
			references_recursion_deep + 1,
			all_buffer,
			ibuf,
			to );
}

/*!
 * @brief Implementation of loading of DNS-name from PDU located in memory.
 *
 * Reads pieces of the name by references.
 *
 * The deep of reference recursion is controlled. If that deep becomes
 * too big then an exception is thrown.
 */
inline void
read_from_memory_buffer_impl(
	unsigned int references_recursion_deep,
	// This should be a buffer that starts with DNS-header.
	std::string_view all_buffer,
	oess_2::io::istream_t & stream,
	std::string & to )
{
	// Because every reference adds at least two octets then the max
	// count of references can be 127 (254/2).
	if( references_recursion_deep > 127u )
		throw std::runtime_error{
			"read_from_memory_buffer_impl: reference recursion too deep"
		};

	bool continue_loop = true;
	do
	{
		continue_loop = std::visit(
				arataga::utils::overloaded{
					[&]( const reference_offset_t & res ) {
						read_reference_from_memory_buffer_impl(
								references_recursion_deep,
								all_buffer,
								res.m_offset,
								to );
						return false; // Stop the loop.
					},
					[&]( const name_length_t & res ) {
						load_next_label( stream, res.m_length, to );
						// The length should be checked.
						dns_format_name_t::ensure_valid_length( to );
						return true; // Loop should be continued.
					},
					[&]( const name_terminator_t & ) {
						to += '\0';
						return false; // Stop the loop.
					}
				},
				load_size_byte( stream ) );
	} while( continue_loop );
}

/*!
 * @brief Loading of DNS-name from PDU located in memory.
 *
 * Reads pieces of the name by references.
 *
 * The deep of reference recursion is controlled. If that deep becomes
 * too big then an exception is thrown.
 */
inline void
read_from_memory_buffer(
	// This should be a buffer that starts with DNS-header.
	std::string_view all_buffer,
	oess_2::io::istream_t & stream,
	std::string & to )
{
	read_from_memory_buffer_impl( 0u, all_buffer, stream, to );
}

//FIXME: read_from_memory_buffer and read_from_stream is very similar.
//Can this code duplication be removed?

/*!
 * @brief Loading of DNS-name from a stream.
 *
 * @attention
 * We can handle references here because in the case of a backward
 * reference we can't rewind the stream.
 */
inline void
read_from_stream(
	oess_2::io::istream_t & stream,
	std::string & to )
{
	bool continue_loop = true;
	do
	{
		continue_loop = std::visit(
				arataga::utils::overloaded{
					[]( const reference_offset_t & ) -> bool {
						throw std::invalid_argument(
								"unable to read references from "
								"ordinary stream, read_from_memory_buffer "
								"must be used instead" );
						return false;
					},
					[&]( const name_length_t & res ) -> bool {
						load_next_label( stream, res.m_length, to );
						// The length should be checked.
						dns_format_name_t::ensure_valid_length( to );

						return true;
					},
					[&to]( const name_terminator_t & ) -> bool {
						to += '\0';
						return false;
					}
				},
				load_size_byte( stream ) );
	} while( continue_loop );
}

inline oess_2::io::ostream_t &
write_to( oess_2::io::ostream_t & o, const dns_format_name_t & name )
{
	o.write( name.raw_value().data(), name.raw_value().size() );

	return o;
}

class from_stream_t
{
	dns_format_name_t & m_what;

public :
	from_stream_t( dns_format_name_t & what ) : m_what( what ) {}

	friend inline oess_2::io::istream_t &
	operator>>( oess_2::io::istream_t & i, from_stream_t && n )
	{
		std::string value;
		read_from_stream( i, value );
		n.m_what = dns_format_name_t{
				dns_format_name_t::already_translated_value_t{ std::move(value) }
		};

		return i;
	}
};

class from_memory_t
{
	std::string_view m_all_buffer;
	dns_format_name_t & m_what;

public :
	from_memory_t(
		std::string_view all_buffer,
		dns_format_name_t & what )
		:	m_all_buffer( all_buffer )
		,	m_what( what )
	{}

	friend inline oess_2::io::istream_t &
	operator>>( oess_2::io::istream_t & i, from_memory_t && n )
	{
		std::string value;
		read_from_memory_buffer( n.m_all_buffer, i, value );
		n.m_what = dns_format_name_t{
				dns_format_name_t::already_translated_value_t{ std::move(value) }
		};

		return i;
	}
};

} /* namespace dns_format_name_tools */

[[nodiscard]]
inline dns_format_name_tools::from_stream_t
from_stream( dns_format_name_t & what ) {
	return dns_format_name_tools::from_stream_t{ what };
}

[[nodiscard]]
inline dns_format_name_tools::from_memory_t
from_memory(
	std::string_view all_buffer,
	dns_format_name_t & name )
{
	return dns_format_name_tools::from_memory_t( all_buffer, name );
}

inline oess_2::io::ostream_t &
operator << ( oess_2::io::ostream_t & o, const dns_format_name_t & n )
{
	return dns_format_name_tools::write_to( o, n );
}

inline std::ostream &
operator << ( std::ostream & o, const dns_format_name_t & n )
{
	return n.dump_to( o );
}

namespace qtype_values
{
	inline constexpr oess_2::ushort_t A = 1;
	inline constexpr oess_2::ushort_t NS = 2;
	inline constexpr oess_2::ushort_t CNAME = 5;
	inline constexpr oess_2::ushort_t SOA = 6;
	inline constexpr oess_2::ushort_t PTR = 12;
	inline constexpr oess_2::ushort_t MX = 15;
	inline constexpr oess_2::ushort_t OPT = 41;
	inline constexpr oess_2::ushort_t AAAA = 28;
}

namespace qclass_values
{
	inline constexpr oess_2::ushort_t IN = 1;
}

//
// dns_question_t
//

/*!
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
struct dns_question_t
{
	dns_question_t()
	{}

	dns_question_t( std::string_view name )
		: m_qname{ name }
		, m_qtype{ qtype_values::A } // A-record
		, m_qclass{ qclass_values::IN }
	{}

	dns_question_t(
		std::string_view name,
		oess_2::ushort_t qtype,
		oess_2::ushort_t qclass )
		: m_qname{ name }
		, m_qtype{ qtype }
		, m_qclass{ qclass }
	{}

	dns_format_name_t m_qname;
	oess_2::ushort_t m_qtype{};
	oess_2::ushort_t m_qclass{};

	oess_2::io::istream_t &
	read_from( oess_2::io::istream_t & i )
	{
		i
			>> from_stream( m_qname )
			>> m_qtype
			>> m_qclass;

		return i;
	}

	oess_2::io::ostream_t &
	write_to( oess_2::io::ostream_t & o ) const
	{
		o
			<< m_qname
			<< m_qtype
			<< m_qclass;

		return o;
	}

	std::ostream &
	dump_to( std::ostream & o ) const
	{
		o
			<<"{ "
			<< "qname: " << m_qname << "; "
			<< "qtype: " << m_qtype << "; "
			<< "qclass: " << m_qclass
			<<" }";

		return o;
	}
};

inline oess_2::io::istream_t &
operator >> ( oess_2::io::istream_t & i, dns_question_t & q )
{
	return q.read_from( i );
}

inline oess_2::io::ostream_t &
operator << ( oess_2::io::ostream_t & o, const dns_question_t & q )
{
	return q.write_to( o );
}

inline std::ostream &
operator << ( std::ostream & o, const dns_question_t & q )
{
	return q.dump_to( o );
}

//
// dns_resource_record_t
//

/*!
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

struct dns_resource_record_t
{
	dns_format_name_t m_name;
	oess_2::ushort_t m_type{};
	oess_2::ushort_t m_class{};
	oess_2::uint_t m_ttl{};
	std::string m_resource_data;

	std::ostream &
	dump_to( std::ostream & o ) const
	{
		o
			<<"{ "
			<< "name: " << m_name << "; "
			<< "type: " << m_type << "; "
			<< "class: " << m_class << "; "
			<< "ttl: " << m_ttl << "; "
			<< "resource_data: " << m_resource_data
			<<" }";

		return o;
	}
};

namespace dns_resource_record_tools {

[[nodiscard]]
inline std::string
read_dns_type_A(
	oess_2::io::istream_t & from,
	oess_2::ushort_t resource_data_length )
{
	static constexpr std::size_t expected_items = 4;

	if( expected_items != resource_data_length )
		throw std::invalid_argument{
			"read_dns_type_A: exactly 4 bytes in resouce data expected"
		};

	oess_2::uchar_t raw_data[ expected_items ];
	from.read( raw_data, expected_items );

	return fmt::format( "{:d}.{:d}.{:d}.{:d}",
			raw_data[ 0 ], raw_data[ 1 ], raw_data[ 2 ], raw_data[ 3 ] );
}

[[nodiscard]]
inline std::string
read_dns_type_AAAA(
	oess_2::io::istream_t & from,
	oess_2::ushort_t resource_data_length )
{
	static constexpr std::size_t expected_items = 8;

	if( expected_items * 2 != resource_data_length )
		throw std::invalid_argument{
			"read_dns_type_AAAA: exactly 16 bytes in resouce data expected"
		};

	oess_2::ushort_t raw_data[ expected_items ];
	from.read( raw_data, expected_items );

	return fmt::format( "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
			raw_data[ 0 ], raw_data[ 1 ], raw_data[ 2 ], raw_data[ 3 ],
			raw_data[ 4 ], raw_data[ 5 ], raw_data[ 6 ], raw_data[ 7 ] );
}

inline void
just_skip_data(
	oess_2::io::istream_t & from,
	oess_2::ushort_t resource_data_size )
{
	from.shift_bytes( resource_data_size );
}

inline dns_resource_record_t
read_from(
	std::string_view all_buffer,
	oess_2::io::istream_t & from )
{
	dns_resource_record_t to;

	from >> from_memory( all_buffer, to.m_name ) >> to.m_type;

	if( to.m_type != qtype_values::OPT )
	{
		oess_2::ushort_t resource_data_length;

		from >> to.m_class >> to.m_ttl >> resource_data_length;

		if( to.m_type == qtype_values::A )
			to.m_resource_data = read_dns_type_A(
					from,
					resource_data_length );
		else if( to.m_type == qtype_values::AAAA )
			to.m_resource_data = read_dns_type_AAAA(
					from,
					resource_data_length );
		else
			// Skip data we don't need.
			just_skip_data( from, resource_data_length );
	}

	return to;
}

class from_memory_t
{
	std::string_view m_all_buffer;
	dns_resource_record_t & m_what;

public :
	from_memory_t(
		std::string_view all_buffer,
		dns_resource_record_t & what )
		:	m_all_buffer( all_buffer )
		,	m_what( what )
	{}

	friend inline oess_2::io::istream_t &
	operator>>( oess_2::io::istream_t & i, from_memory_t && n )
	{
		n.m_what = read_from( n.m_all_buffer, i );
		return i;
	}
};

} /* namespace dns_resource_record_tools */

[[nodiscard]]
inline dns_resource_record_tools::from_memory_t
from_memory(
	std::string_view all_buffer,
	dns_resource_record_t & rr )
{
	return dns_resource_record_tools::from_memory_t( all_buffer, rr );
}

inline std::ostream &
operator << ( std::ostream & o, const dns_resource_record_t & rr )
{
	return rr.dump_to( o );
}

} /* namespace arataga::dns_resolver */

