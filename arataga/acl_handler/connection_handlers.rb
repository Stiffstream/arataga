require 'mxx_ru/cpp'

MxxRu::Cpp::lib_target {

	target 'lib/acl_connection_handlers'

	required_prj 'fmt-prj.rb'
	required_prj 'spdlog-prj.rb'
	required_prj 'asio-prj.rb'
   required_prj 'nodejs/http_parser_mxxru/prj.rb'

	cpp_source 'connection_handler_ifaces.cpp'
	cpp_source 'handlers/protocol_detection.cpp'
	cpp_source 'handlers/data_transfer.cpp'
	cpp_source 'handlers/socks5.cpp'

   cpp_source 'handlers/http/basics.cpp'
   cpp_source 'handlers/http/negative_response_sender.cpp'
   cpp_source 'handlers/http/initial_handler.cpp'
   cpp_source 'handlers/http/authentification_handler.cpp'
   cpp_source 'handlers/http/dns_lookup_handler.cpp'
   cpp_source 'handlers/http/target_connector.cpp'
   cpp_source 'handlers/http/connect_method_handler.cpp'
   cpp_source 'handlers/http/ordinary_method_handler.cpp'
}

