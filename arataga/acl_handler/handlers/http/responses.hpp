/*!
 * @file
 * @brief HTTP-responses to be sent to users.
 */

#pragma once

#include <string_view>

namespace arataga::acl_handler
{

namespace handlers::http
{

using namespace arataga::utils::string_literals;

inline constexpr auto
response_bad_request_parse_error_detected =
	"HTTP/1.1 400 Bad Request\r\n"
	"connection: close\r\n"
	"content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>400 Bad Request</title></head>\r\n"
	"<body><h2>400 Bad Request</h2>"
	"<p>Unable to parse incoming request.</p>"
	"</body></html>\r\n"_static_str;

inline constexpr auto
response_bad_request_unexpected_parsing_error =
	"HTTP/1.1 400 Bad Request\r\n"
	"connection: close\r\n"
	"content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>400 Bad Request</title></head>\r\n"
	"<body><h2>400 Bad Request</h2>"
	"<p>Unexpected request parsing error.</p>"
	"</body></html>\r\n"_static_str;

inline constexpr auto
response_bad_request_auth_params_extraction_failure =
	"HTTP/1.1 400 Bad Request\r\n"
	"connection: close\r\n"
	"content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>400 Bad Request</title></head>\r\n"
	"<body><h2>400 Bad Request</h2>"
	"<p>An attempt to extract username/password from Proxy-Authorization failed.</p>"
	"</body></html>\r\n"_static_str;

inline constexpr auto
response_bad_request_target_host_extraction_failure =
	"HTTP/1.1 400 Bad Request\r\n"
	"connection: close\r\n"
	"content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>400 Bad Request</title></head>\r\n"
	"<body><h2>400 Bad Request</h2>"
	"<p>An attempt to detect target-host and target-port from incoming request failed.</p>"
	"</body></html>\r\n"_static_str;

inline constexpr auto
response_bad_request_invalid_request_target =
	"HTTP/1.1 400 Bad Request\r\n"
	"connection: close\r\n"
	"content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>400 Bad Request</title></head>\r\n"
	"<body><h2>400 Bad Request</h2>"
	"<p>Invalid request-target format.</p>"
	"</body></html>\r\n"_static_str;

inline constexpr auto
response_request_timeout_headers_complete_timeout =
	"HTTP/1.1 408 Request Timeout\r\n"
	"connection: close\r\n"
	"content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>408 Request Timeout</title></head>\r\n"
	"<body><h2>408 Request Timeout</h2>"
	"<p>Client sends the request too slowly (timeout.http.headers_complete)</p>"
	"</body></html>\r\n"_static_str;

inline constexpr auto
response_proxy_auth_required_auth_timeout =
	"HTTP/1.1 407 Proxy Authentication Required\r\n"
	"connection: close\r\n"
	"content-type: text/html; charset=utf-8\r\n"
	"proxy-authenticate: Basic\r\n"
	"\r\n"
	"<html><head><title>407 Proxy Authentication Required</title></head>\r\n"
	"<body><h2>407 Proxy Authentication Required</h2>"
	"<p>Unable to authentificate (timeout.autentification)</p>"
	"</body></html>\r\n"_static_str;

inline constexpr auto
response_proxy_auth_required_not_authorized =
	"HTTP/1.1 407 Proxy Authentication Required\r\n"
	"connection: close\r\n"
	"content-type: text/html; charset=utf-8\r\n"
	"proxy-authenticate: Basic\r\n"
	"\r\n"
	"<html><head><title>407 Proxy Authentication Required</title></head>\r\n"
	"<body><h2>407 Proxy Authentication Required</h2>"
	"<p>Access to requested resource disallowed by administrator or you need "
	"valid username/password to use this resource</p>"
	"</body></html>\r\n"_static_str;

inline constexpr auto
response_request_timeout_dns_lookup_timeout =
	"HTTP/1.1 408 Request Timeout\r\n"
	"connection: close\r\n"
	"content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>408 Request Timeout</title></head>\r\n"
	"<body><h2>408 Request Timeout</h2>"
	"<p>DNS lookup procedure timed out (timeout.dns_resolving)</p>"
	"</body></html>\r\n"_static_str;

inline constexpr auto
response_bad_gateway_dns_lookup_failure =
	"HTTP/1.1 502 Bad Gateway\r\n"
	"connection: close\r\n"
	"content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>502 Bad Gateway</title></head>\r\n"
	"<body><h2>502 Bad Gateway</h2>"
	"<p>DNS lookup procedure failed</p>"
	"</body></html>\r\n"_static_str;

inline constexpr auto
response_bad_gateway_connect_timeout =
	"HTTP/1.1 502 Bad Gateway\r\n"
	"connection: close\r\n"
	"content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>502 Bad Gateway</title></head>\r\n"
	"<body><h2>502 Bad Gateway</h2>"
	"<p>Connect to the target host timed out (timeout.connect_target)</p>"
	"</body></html>\r\n"_static_str;

inline constexpr auto
response_bad_gateway_connect_failure =
	"HTTP/1.1 502 Bad Gateway\r\n"
	"connection: close\r\n"
	"content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>502 Bad Gateway</title></head>\r\n"
	"<body><h2>502 Bad Gateway</h2>"
	"<p>Unable to connect to the target host</p>"
	"</body></html>\r\n"_static_str;

inline constexpr auto
response_bad_gateway_invalid_response =
	"HTTP/1.1 502 Bad Gateway\r\n"
	"connection: close\r\n"
	"content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>502 Bad Gateway</title></head>\r\n"
	"<body><h2>502 Bad Gateway</h2>"
	"<p>Invalid respose received from the target host</p>"
	"</body></html>\r\n"_static_str;

inline constexpr auto
response_internal_server_error =
	"HTTP/1.1 500 Internal Server Error\r\n"
	"connection: close\r\n"
	"content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>500 Internal Server Error</title></head>\r\n"
	"<body><h2>500 Internal Server Error</h2>"
	"<p>The request can't be processed</p>"
	"</body></html>\r\n"_static_str;

inline constexpr auto
response_ok_for_connect_method =
	"HTTP/1.1 200 Ok\r\n"
	"\r\n"_static_str;

} /* namespace arataga::acl_handler */

} /* namespace handlers::http */

