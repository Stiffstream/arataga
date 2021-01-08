require 'mxx_ru/cpp'

MxxRu::Cpp::lib_target {

	target 'lib/user_list_auth_data'

	required_prj 'asio-prj.rb'
	required_prj 'fmt-prj.rb'

	cpp_source 'user_list_auth_data.cpp'
}

