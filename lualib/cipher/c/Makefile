CC=gcc -g  $(CFLAGS) -DLINUX -w
SHARED_FLAG = -fPIC -shared

LUAJIT_INC = ../../../luajit/include/luajit-2.1
LUAJIT_LIB = ../../../luajit/lib

INC += -I./
INC += -I$(LUAJIT_INC)

LIB += -L$(LUAJIT_LIB) -llua
SOURCES = $(foreach d,.,$(wildcard $(d)/*.c))
OBJS = $(patsubst %.c, %.o, $(SOURCES))

PROJECT = cipher.so

CC += $(SHARED_FLAG)

all : $(PROJECT)

$(PROJECT) : $(OBJS)
	$(CC) $(SHARED_FLAG) -o $(PROJECT) $(OBJS) $(LIB)
	echo $(OBJS)
	echo $(SOURCES)
	@echo ""
	@echo "+--------------------------------------------+"
	@echo "|            Finish compilation              |"
	@echo "+--------------------------------------------+"
	@echo "|         Thanks using cipher.so             |"
	@echo "|   copyright(c)Wang Yaofu  voipman@qq.com   |"
	@echo "+--------------------------------------------+"

clean:
	rm -rf *.o *.a

%.o : %.cpp
	$(CC) $(SHARED_FLAG) -c $< $(INC)
%.o : %.c
	$(CC) $(SHARED_FLAG) -c $< $(INC)
