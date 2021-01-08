require 'mxx_ru/binary_unittest'

path = 'tests/http/http_fields'

MxxRu::setup_target(
	MxxRu::BinaryUnittestTarget.new( "#{path}/prj.ut.rb", "#{path}/prj.rb" )
)

