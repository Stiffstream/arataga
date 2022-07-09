MxxRu::arch_externals :args do |e|
  e.url 'https://github.com/Taywee/args/archive/78e27faf75ff7d20f232f11ffcef65cde43c449d.tar.gz'

  e.map_file 'args.hxx' => 'args/*'
end

MxxRu::arch_externals :asio do |e|
  e.url 'https://github.com/chriskohlhoff/asio/archive/asio-1-18-1.tar.gz'

  e.map_dir 'asio/include' => 'asio'
end

MxxRu::arch_externals :spdlog do |e|
  e.url 'https://github.com/gabime/spdlog/archive/v1.10.0.tar.gz'

  e.map_dir 'include/spdlog' => 'spdlog/include'
  e.map_dir 'src' => 'spdlog'
end

MxxRu::arch_externals :fmt do |e|
  e.url 'https://github.com/fmtlib/fmt/archive/9.0.0.tar.gz'

  e.map_dir 'include' => 'fmt'
  e.map_dir 'src' => 'fmt'
  e.map_dir 'support' => 'fmt'
  e.map_file 'CMakeLists.txt' => 'fmt/*'
  e.map_file 'README.rst' => 'fmt/*'
  e.map_file 'ChangeLog.rst' => 'fmt/*'
end

MxxRu::arch_externals :so5 do |e|
  e.url 'https://github.com/Stiffstream/sobjectizer/archive/v.5.7.4.1.tar.gz'
  e.map_dir 'dev/so_5' => './'
end

MxxRu::arch_externals :so5extra do |e|
  e.url 'https://github.com/Stiffstream/so5extra/archive/v.1.5.2.tar.gz'
  e.map_dir 'dev/so_5_extra' => './'
end

MxxRu::arch_externals :noexcept_ctcheck do |e|
  e.url 'https://github.com/Stiffstream/noexcept-ctcheck/archive/v.1.0.0.tar.gz'

  e.map_dir 'noexcept_ctcheck' => './'
end

MxxRu::arch_externals :restinio do |e|
  e.url 'https://github.com/Stiffstream/restinio/archive/v.0.6.13.tar.gz'

  e.map_dir 'dev/restinio' => './'
end

MxxRu::arch_externals :nodejs_http_parser do |e|
  e.url 'https://github.com/nodejs/http-parser/archive/v2.9.4.tar.gz'

  e.map_file 'http_parser.h' => 'nodejs/http_parser/*'
  e.map_file 'http_parser.c' => 'nodejs/http_parser/*'
end

MxxRu::arch_externals :nodejs_http_parser_mxxru do |e|
  e.url 'https://github.com/Stiffstream/nodejs_http_parser_mxxru/archive/v.0.2.1.tar.gz'

  e.map_dir 'dev/nodejs/http_parser_mxxru' => 'nodejs'
end

MxxRu::arch_externals :doctest do |e|
  e.url 'https://github.com/onqtam/doctest/archive/2.4.4.tar.gz'

  e.map_file 'doctest/doctest.h' => 'doctest/*'
end

MxxRu::arch_externals :oess_2 do |e|
  e.url 'https://sourceforge.net/projects/sobjectizer/files/oess/oess-2/oess-2.2.3-full.tar.bz2'

  e.map_dir 'dev/cpp_util_2' => './'
  e.map_dir 'dev/oess_2' => './'
end

