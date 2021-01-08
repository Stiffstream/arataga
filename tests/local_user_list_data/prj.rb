require 'mxx_ru/cpp'

MxxRu::Cpp::exe_target {

	target 'test-bin/ut_main_worker_local_user_list_data'

	lib 'stdc++fs'

	required_prj 'arataga/user_list_auth_data.rb'

	cpp_source 'main.cpp'
}

