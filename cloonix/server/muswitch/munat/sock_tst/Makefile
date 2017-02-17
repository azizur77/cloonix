OBJ_DIR=./obj/
WARNINGS=-Wall 
SEXE = sock_srv
CEXE = sock_cli

SSRC = sock_srv.c \
       sock_utils.c 

CSRC = sock_cli.c \
       sock_utils.c 

VPATH=src
INCLUDES= -I./src
LIBS = 
CFLAGS+= -g $(WARNINGS) $(INCLUDES)

all: $(shell mkdir -p ./obj) $(SEXE) $(CEXE)

SOBJ = $(SSRC:.c=.o)
SOBJS = $(addprefix $(OBJ_DIR), $(SOBJ))

COBJ = $(CSRC:.c=.o)
COBJS = $(addprefix $(OBJ_DIR), $(COBJ))

$(OBJ_DIR)%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

$(SEXE): $(SOBJS)
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $(SEXE) 

$(CEXE): $(COBJS)
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $(CEXE) 

clean:
	@-rm -vrf $(OBJ_DIR) $(SEXE) $(CEXE)

