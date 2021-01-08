require 'mxx_ru/binary_unittest'

path = 'tests/socks5/bind_pdu'

MxxRu::setup_target(
	MxxRu::BinaryUnittestTarget.new( "#{path}/prj.ut.rb", "#{path}/prj.rb" )
)

