gem 'Mxx_ru', '>= 1.3.0'

require 'mxx_ru/cpp'

MxxRu::Cpp::composite_target {
  include_path './asio/include', Mxx_ru::Cpp::Target::OPT_UPSPREAD

  define 'ASIO_STANDALONE', Mxx_ru::Cpp::Target::OPT_UPSPREAD
}

