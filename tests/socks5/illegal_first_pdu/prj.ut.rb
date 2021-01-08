require 'mxx_ru/binary_unittest'

path = 'tests/socks5/illegal_first_pdu'

MxxRu::setup_target(
	MxxRu::BinaryUnittestTarget.new( "#{path}/prj.ut.rb", "#{path}/prj.rb" )
)

