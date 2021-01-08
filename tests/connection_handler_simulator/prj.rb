require 'mxx_ru/cpp'

MxxRu::Cpp::lib_target {

	target 'test-bin/connection_handler_simulator'

	required_prj 'fmt-prj.rb'
	required_prj 'spdlog-prj.rb'
	required_prj 'asio-prj.rb'
	required_prj 'so_5/prj_s.rb'
	required_prj 'arataga/logging/logging.rb'
	required_prj 'arataga/acl_handler/connection_handlers.rb'

	cpp_source 'impl.cpp'
}

