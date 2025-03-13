# Makefile for libusb based examples
BTSTACK_ROOT ?= ..

CORE += main.c btstack_stdin_posix.c btstack_tlv_posix.c hci_dump_posix_fs.c

COMMON += hci_transport_h2_libusb.c btstack_run_loop_posix.c le_device_db_tlv.c btstack_link_key_db_tlv.c wav_util.c btstack_network_posix.c
COMMON += btstack_audio_portaudio.c btstack_chipset_zephyr.c btstack_chipset_realtek.c rijndael.c btstack_signal.c


VPATH += ${BTSTACK_ROOT}/src
VPATH += ${BTSTACK_ROOT}/src/ble
VPATH += ${BTSTACK_ROOT}/src/ble/gatt-service
VPATH += ${BTSTACK_ROOT}/src/classic
VPATH += ${BTSTACK_ROOT}/src/mesh
VPATH += ${BTSTACK_ROOT}/src/mesh/gatt-service
VPATH += ${BTSTACK_ROOT}/example
VPATH += ${BTSTACK_ROOT}/3rd-party/bluedroid/decoder/srce
VPATH += ${BTSTACK_ROOT}/3rd-party/bluedroid/encoder/srce
VPATH += ${BTSTACK_ROOT}/3rd-party/hxcmod-player
VPATH += ${BTSTACK_ROOT}/3rd-party/hxcmod-player
VPATH += ${BTSTACK_ROOT}/3rd-party/hxcmod-player/mods
VPATH += ${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/
VPATH += ${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/ipv4
VPATH += ${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/ipv6
VPATH += ${BTSTACK_ROOT}/3rd-party/lwip/core/src/netif
VPATH += ${BTSTACK_ROOT}/3rd-party/lwip/core/src/apps/http
VPATH += ${BTSTACK_ROOT}/3rd-party/lwip/dhcp-server
VPATH += ${BTSTACK_ROOT}/3rd-party/md5
VPATH += ${BTSTACK_ROOT}/3rd-party/micro-ecc
VPATH += ${BTSTACK_ROOT}/3rd-party/yxml
VPATH += ${BTSTACK_ROOT}/platform/lwip
VPATH += ${BTSTACK_ROOT}/platform/lwip/port


CFLAGS += -I.
CFLAGS += -I${BTSTACK_ROOT}/src/ble
CFLAGS += -I${BTSTACK_ROOT}/src/classic
CFLAGS += -I${BTSTACK_ROOT}/src/mesh
CFLAGS += -I${BTSTACK_ROOT}/src
CFLAGS += -I${BTSTACK_ROOT}/3rd-party/bluedroid/decoder/include
CFLAGS += -I${BTSTACK_ROOT}/3rd-party/bluedroid/encoder/include
CFLAGS += -I${BTSTACK_ROOT}/3rd-party/hxcmod-player
CFLAGS += -I${BTSTACK_ROOT}/3rd-party/lwip/core/src/include/
CFLAGS += -I${BTSTACK_ROOT}/3rd-party/lwip/dhcp-server
CFLAGS += -I${BTSTACK_ROOT}/3rd-party/md5
CFLAGS += -I${BTSTACK_ROOT}/3rd-party/micro-ecc
CFLAGS += -I${BTSTACK_ROOT}/3rd-party/yxml
CFLAGS += -I${BTSTACK_ROOT}/platform/lwip
CFLAGS += -I${BTSTACK_ROOT}/platform/lwip/port

# for CVSD/SBC PLC
LDFLAGS += -lm

CORE += \
	btstack_memory.c            \
	btstack_linked_list.c	    \
	btstack_memory_pool.c       \
	btstack_run_loop.c		    \
	btstack_util.c 	            \

COMMON += \
	ad_parser.c                 \
	hci.c			            \
	hci_cmd.c		            \
	hci_dump.c		            \
	hci_event.c                 \
	l2cap.c			            \
	l2cap_signaling.c	        \
	btstack_audio.c             \
	btstack_tlv.c               \
	btstack_crypto.c            \
	uECC.c                      \

ATT	+= \
	att_dispatch.c       	    \

GATT_SERVER += \
	att_db.c					\
	att_server.c        	    \

GATT_CLIENT += \
	gatt_client.c        	    			\
	battery_service_client.c 				\
	device_information_service_client.c 	\
	scan_parameters_service_client.c 	    \
	hids_client.c 	

# .h for .gatt
EXAMPLES_GATT_H_FILES = $(EXAMPLES_GATT_FILES:.gatt=.h)

# .o for .c
CORE_OBJ    = $(CORE:.c=.o)
COMMON_OBJ  = $(COMMON:.c=.o)
ATT_OBJ     = $(ATT:.c=.o)
GATT_CLIENT_OBJ = $(GATT_CLIENT:.c=.o)
GATT_SERVER_OBJ = $(GATT_SERVER:.c=.o)

CFLAGS  += -g -std=c99 -Wall -Wmissing-prototypes -Wstrict-prototypes -Wshadow -Wunused-parameter -Wredundant-decls -Wsign-compare -Wswitch-default
# CFLAGS += -Werror
# CFLAGS += -pedantic

# only LLVM
# CFLAGS += -Wnewline-eof
# CFLAGS += -Wc11-extensions
# CFLAGS += -Wgnu-empty-initializer

CFLAGS += -I${BTSTACK_ROOT}/platform/posix    \
		  -I${BTSTACK_ROOT}/platform/embedded \
		  -I${BTSTACK_ROOT}/3rd-party/tinydir \
		  -I${BTSTACK_ROOT}/3rd-party/rijndael \
		  -I${BTSTACK_ROOT}/chipset/realtek \
		  -I${BTSTACK_ROOT}/chipset/zephyr

VPATH += ${BTSTACK_ROOT}/3rd-party/rijndael
VPATH += ${BTSTACK_ROOT}/platform/embedded
VPATH += ${BTSTACK_ROOT}/platform/posix
VPATH += ${BTSTACK_ROOT}/platform/libusb
VPATH += ${BTSTACK_ROOT}/chipset/csr
VPATH += ${BTSTACK_ROOT}/chipset/realtek
VPATH += ${BTSTACK_ROOT}/chipset/zephyr

# use pkg-config
CFLAGS  += $(shell pkg-config libusb-1.0 --cflags)
LDFLAGS += $(shell pkg-config libusb-1.0 --libs)

# add pthread for ctrl-c signal handler
LDFLAGS += -lpthread

# use pkg-config for portaudio
# CFLAGS  += $(shell pkg-config portaudio-2.0 --cflags) -DHAVE_PORTAUDIO
# LDFLAGS += $(shell pkg-config portaudio-2.0 --libs)

default_target: all

# compile .gatt descriptions
%.h: %.gatt
	python3 ${BTSTACK_ROOT}/tool/compile_gatt.py $< $@

le_pairing.o: le_pairing.c
	${CC} ${CFLAGS} -c $^ -o $@

demo_le:${CORE_OBJ} ${COMMON_OBJ} ${ATT_OBJ} ${GATT_SERVER_OBJ} ${GATT_SERVER_OBJ} ${GATT_CLIENT_OBJ} sm.o le_pairing.o
	${CC} $^ ${LDFLAGS} -o $@

le_pairing_pfs.o: le_pairing.c
	${CC} ${CFLAGS} -c $^ -DENABLE_LE_PFS -o $@

sm_l5s.o: sm_l5s.c
	${CC} ${CFLAGS} -c $^ -DENABLE_LE_PFS -o $@

demo_l5s:${CORE_OBJ} ${COMMON_OBJ} ${ATT_OBJ} ${GATT_SERVER_OBJ} ${GATT_SERVER_OBJ} ${GATT_CLIENT_OBJ} sm_l5s.o le_pairing_pfs.o
	${CC} $^ ${LDFLAGS} -o $@

clean:
	rm -f demo_l5s  ${EXAMPLES_GATT_H_FILES}
	rm -f  *.o *.out *.hex *.exe *.wav *.sbc 
	rm -rf *.dSYM
	rm -rf ${BTSTACK_ROOT}/src/*.o
	rm -rf ${BTSTACK_ROOT}/src/ble/*.o
	rm -rf ${BTSTACK_ROOT}/src/ble/gatt-service/*.o
	rm -rf ${BTSTACK_ROOT}/src/classic/*.o
	rm -rf ${BTSTACK_ROOT}/example/*.o

clean_src:
	rm -rf * ${BTSTACK_ROOT}/src/*.o
	rm -rf * ${BTSTACK_ROOT}/src/classic/*.o
	rm -rf * ${BTSTACK_ROOT}/src/ble/*.o
	rm -rf * ${BTSTACK_ROOT}/platform/embedded/*.o

all: demo_l5s demo_le

