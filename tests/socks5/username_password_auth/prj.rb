require 'mxx_ru/cpp'

MxxRu::Cpp::exe_target {

	target 'test-bin/ut_socks5_username_password_auth'

	required_prj 'fmt-prj.rb'
	required_prj 'asio-prj.rb'
	required_prj 'restinio/platform_specific_libs.rb'

	required_prj 'tests/connection_handler_simulator/prj.rb'

	cpp_source 'main.cpp'
}

