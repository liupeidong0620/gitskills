EXE=netpas_client
HEADERS=config.h netpas_client.h util_lib.h

CFLAGS += -DNETPAS_EXE=\"${EXE}\"
LIB_DIR=../submodules/netpas_msg_lib/bin
LIB=libmsg_lib.a

All: client

client: netpas_client.o util_lib.o
	gcc ${CFLAGS} -o ${EXE} netpas_client.o util_lib.o ${LIB_DIR}/${LIB}
	strip ${EXE}

test: mytest.o util_lib.o
	gcc ${CFLAGS} -o mytest mytest.o util_lib.o ${LIB_DIR}/${LIB}
	strip mytest

%.o:%.c ${HEADERS}
	gcc ${CFLAGS} -W -Wall -c $< -o $@
clean:
	rm -f *.o
	rm -f ${EXE}
