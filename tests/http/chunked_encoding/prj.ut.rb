require 'mxx_ru/binary_unittest'

path = 'tests/http/chunked_encoding'

MxxRu::setup_target(
	MxxRu::BinaryUnittestTarget.new( "#{path}/prj.ut.rb", "#{path}/prj.rb" )
)

