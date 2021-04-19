require 'rubygems'

gem 'Mxx_ru', '>= 1.3.0'

require 'mxx_ru/binary_unittest'

path = 'tests/dns_types'

MxxRu::setup_target(
  MxxRu::BinaryUnittestTarget.new(
    "#{path}/prj.ut.rb",
    "#{path}/prj.rb" ) )

