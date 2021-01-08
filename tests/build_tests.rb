gem 'Mxx_ru', '>=1.6.4'

require 'mxx_ru/cpp'

MxxRu::Cpp::composite_target {
	required_prj 'tests/config_parser/prj.ut.rb'
	required_prj 'tests/local_user_list_data/prj.ut.rb'
	required_prj 'tests/socks5/build_tests.rb'
	required_prj 'tests/http/build_tests.rb'
}

