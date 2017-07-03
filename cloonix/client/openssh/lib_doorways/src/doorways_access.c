/****************************************************************************/
/* Copyright (C) 2006-2017 Cloonix <clownix@clownix.net>  License GPL-3.0+  */
/****************************************************************************/
/*                                                                          */
/*   This program is free software: you can redistribute it and/or modify   */
/*   it under the terms of the GNU General Public License as published by   */
/*   the Free Software Foundation, either version 3 of the License, or      */
/*   (at your option) any later version.                                    */
/*                                                                          */
/*   This program is distributed in the hope that it will be useful,        */
/*   but WITHOUT ANY WARRANTY; without even the implied warranty of         */
/*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          */
/*   GNU General Public License for more details.                           */
/*                                                                          */
/*   You should have received a copy of the GNU General Public License      */
/*   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */
/*                                                                          */
/****************************************************************************/
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "io_clownix.h"
#include "doorways_sock.h"
#include "lib_doorways.h"


static int g_door_llid;
static int g_connect_llid;
static char g_cloonix_passwd[MSG_DIGEST_LEN+1];
static char g_cloonix_doors[MAX_PATH_LEN];


/*****************************************************************************/
void heartbeat(int delta)
{
  static int count = 0;
  (void) delta;
  count++;
  if (count == 500)
    {
    if (!g_door_llid)
      {
      close(get_fd_with_llid(g_connect_llid));
      doorways_sock_client_inet_delete(g_connect_llid);
      fprintf(stderr, "\nTimeout during connect: %s\n\n", g_cloonix_doors);
      exit(1);
      }
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void cb_doors_rx_nominal(int len, char *buf)
{
(void) len;
(void) buf;
fprintf(stderr, "\nTODO\n");
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void cb_doors_rx(int llid, int tid, int type, int val, int len, char *buf)
{
  char nat_name[MAX_NAME_LEN];
  (void) llid;
  (void) tid;
  if (type == doors_type_openssh)
    {
    if ((val == doors_val_init_link_ok) || (val == doors_val_init_link_ko))
      {
      if (sscanf(buf,"OK OPENSSH_CLI_DOORS_RESP nat=%s", nat_name) == 1)
        {
        fprintf(stderr, "TODO\n");
        }
      else
        {
        fprintf(stderr, "ERROR1: %s\n", buf);
        exit(1);
        }
      }
    else if (val == doors_val_none)
      {
      cb_doors_rx_nominal(len, buf);
      }
    }
  else
    {
    fprintf(stderr, "ERROR3: %s\n", buf);
    exit(1);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void cb_doors_end(int llid)
{
  (void) llid;
  fprintf(stderr, "\n%s\n", __FILE__);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int callback_connect(void *ptr, int llid, int fd)
{
  char buf[2*MAX_NAME_LEN];
  (void) ptr;
  if (g_door_llid == 0)
    {
    g_door_llid = doorways_sock_client_inet_end(doors_type_dbssh, llid, fd,
                                                g_cloonix_passwd,
                                                cb_doors_end, cb_doors_rx);
    if (!g_door_llid)
      {
      fprintf(stderr, "\nConnect not possible: %s\n\n", g_cloonix_doors);
      exit(1);
      }
    memset(buf, 0, 2*MAX_NAME_LEN);
    snprintf(buf, 2*MAX_NAME_LEN - 1, "OPENSSH_CLI_DOORS_REQ nat=%s", "nat");
    if (doorways_tx(g_door_llid, 0, doors_type_dbssh,
                    doors_val_init_link, strlen(buf)+1, buf))
      {
      fprintf(stderr, "ERROR INIT SEQ:\n%d, %s\n\n", (int) strlen(buf), buf);
      exit(1);
      }
    }
  else
    fprintf(stderr, "TWO CONNECTS FOR ONE REQUEST");
  return 0;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int cloonix_connect_remote(char *cloonix_doors)
{
  int ip, port;
  if (get_ip_port_from_path(cloonix_doors, &ip, &port) == -1)
    {
    fprintf(stderr, "\nBad address %s\n\n", cloonix_doors);
    exit(1);
    }
  g_door_llid = 0;
  g_connect_llid = doorways_sock_client_inet_start(ip,port,callback_connect);
  if (!g_connect_llid)
    {
    fprintf(stderr, "\nCannot reach doorways %s\n\n", cloonix_doors);
    exit(1);
    }
  return 0;
}
/*--------------------------------------------------------------------------*/



/****************************************************************************/
void doorways_init(char *cloonix_doors, char *cloonix_passwd)
{
  memset(g_cloonix_passwd, 0, MSG_DIGEST_LEN+1);
  memset(g_cloonix_doors, 0, MAX_PATH_LEN);
  strncpy(g_cloonix_passwd, cloonix_passwd, MSG_DIGEST_LEN); 
  strncpy(g_cloonix_doors, cloonix_doors, MAX_PATH_LEN);
  if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    {
    fprintf(stderr, "signal error");
    exit(1);
    }
  doorways_sock_init();
  msg_mngt_init("openssh", IO_MAX_BUF_LEN);
  msg_mngt_heartbeat_init(heartbeat);
  cloonix_connect_remote(g_cloonix_doors);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void doorways_loop(void)
{
  msg_mngt_loop();
}
/*--------------------------------------------------------------------------*/

