require 'rubygems'

gem 'Mxx_ru', '>= 1.3.0'

require 'mxx_ru/cpp'

MxxRu::Cpp::exe_target {

  target 'test-bin/ut_dns_types'

  required_prj 'oess_2/io/prj_s.rb'
  required_prj 'fmt-prj.rb'

  cpp_source 'main.cpp'
}

