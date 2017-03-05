/*
 * Stolen for cloonix from:
 * Dropbear - a SSH2 server
 * SSH client implementation
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * Copyright (c) 2004 by Mihnea Stoenescu
 * All rights reserved.
*/

#include "includes.h"
#include "dbutil.h"
#include "runopts.h"
#include "session.h"
#include "io_clownix.h"


int cloonix_connect_remote(char *cloonix_doors, 
                           char *vmname,
                           char *password);
void cloonix_session_loop(void);


int main_i_run_in_kvm(void)
{
  return 0;
}

char *main_cloonix_tree_dir(void)
{
  return NULL;
}


/****************************************************************************/
int main(int argc, char ** argv)
{
  cli_getopts(argc, argv);
  if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    KOUT("signal() error");
  cloonix_connect_remote(cli_opts.cloonix_doors, 
                         cli_opts.vmname,
                         cli_opts.cloonix_password);
  cloonix_session_loop();
  return -1;
}
/*--------------------------------------------------------------------------*/

