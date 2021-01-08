FROM ubuntu:18.04 as arataga-build

# Prepare build environment
RUN apt-get update 
RUN apt-get -qq -y install software-properties-common
RUN add-apt-repository ppa:ubuntu-toolchain-r/test
RUN apt-get update && \
    apt-get -qq -y install g++-10
RUN apt-get -qq -y install ruby curl pkg-config libtool
RUN gem install Mxx_ru

RUN mkdir /tmp/arataga-build
COPY arataga /tmp/arataga-build/arataga
COPY *.rb /tmp/arataga-build/

RUN echo "*** Building arataga ***" \
    && cd /tmp/arataga-build \
	 && mxxruexternals \
	 && MXX_RU_CPP_TOOLSET="gcc_linux cpp_compiler_name=g++-10 c_compiler_name=gcc-10 linker_name=g++-10" ruby build.rb --mxx-cpp-release \
	 && cp target/release/bin/arataga /root \
	 && cd /root \
	 && rm -rf /tmp/arataga-build

FROM ubuntu:18.04 as arataga

RUN apt-get update 
RUN apt-get -qq -y install software-properties-common
RUN add-apt-repository ppa:ubuntu-toolchain-r/test
RUN apt-get update && \
    apt-get -qq -y install g++-10

COPY --from=arataga-build /root/arataga /root

RUN mkdir /root/cfg

RUN echo "log_level info\n\
timeout.protocol_detection 15s\n\
timeout.http.headers_complete 10s\n\
acl auto, port=5001, in_ip=0.0.0.0, out_ip=0.0.0.0" > /root/cfg/local-config.cfg

RUN echo "0.0.0.0 5001 user 12345 = 0 0 0 1" > /root/cfg/local-user-list.cfg

EXPOSE 8088
EXPOSE 5001
WORKDIR /root

# Start arataga
CMD ~/arataga --no-daemonize \
	--admin-http-ip=0.0.0.0 --admin-http-port=8088 \
	--admin-token=arataga-admin-entry \
	--local-config-path=/root/cfg \
	--log-target=stdout \
	--log-level=debug

