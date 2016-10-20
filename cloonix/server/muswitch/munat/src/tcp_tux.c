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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>


#include "ioc.h"
//#include "sock_fd.h"
#include "main.h"
#include "machine.h"
#include "utils.h"
//#include "bootp_input.h"
//#include "packets_io.h"
//#include "llid_slirptux.h"
#include "clo_tcp.h"
#include "tcp_tux.h"

void tcp_connect_wait_management(t_connect cb, t_tcp_id *tcpid, int fd,
                                 struct sockaddr *addr, int addr_len);

/*****************************************************************************/
static int get_out_ip_addr(u32_t local_ip)
{
  int out_ip_addr, our_ip_dns, our_ip_gw, host_ip_dns;
  if (ip_string_to_int (&our_ip_dns, get_dns_given2guests()))
    KOUT(" ");
  if (ip_string_to_int (&our_ip_gw, get_gw_given2guests()))
    KOUT(" ");
  if ((int) local_ip ==  our_ip_dns)
    {
    if (ip_string_to_int(&host_ip_dns, get_dns_from_resolv()))
      KOUT(" ");
    out_ip_addr = host_ip_dns;
    }
  else if ((int) local_ip == our_ip_gw)
    {
    if (!strcmp(get_dns_from_resolv(), get_dns_given2guests()))
      ip_string_to_int(&out_ip_addr, get_gw_given2guests());
    else
      ip_string_to_int(&out_ip_addr, "127.0.0.1");
    }
  else
    out_ip_addr = local_ip;
  return out_ip_addr;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void tcp_tux_socket_create_and_connect_to_tcp(t_connect cb, t_tcp_id *tcpid)
{
  int opt=1, fd, out_ip_addr, len;
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(struct sockaddr_in));
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd <= 0)
    KOUT(" ");
  nonblock_fd(fd);
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt ));
  addr.sin_family = AF_INET;
  out_ip_addr = get_out_ip_addr(tcpid->local_ip);
  addr.sin_addr.s_addr = htonl(out_ip_addr);
  addr.sin_port = htons(tcpid->local_port);
  len = sizeof (struct sockaddr_in);
  tcp_connect_wait_management(cb, tcpid, fd, (struct sockaddr *) (&addr), len);
}
/*---------------------------------------------------------------------------*/

