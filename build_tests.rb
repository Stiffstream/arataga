gem 'Mxx_ru', '>=1.6.4'

require 'mxx_ru/cpp'

MxxRu::Cpp::composite_target {
	required_prj 'tests/build_tests.rb'
}
