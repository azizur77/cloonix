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
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <signal.h>


#include "ioc.h"
#include "tun_tap.h"
#include "sock_fd.h"

/*--------------------------------------------------------------------------*/
static int glob_ifindex;
static int g_llid_raw;
static int g_fd_raw;
static char g_raw_name[MAX_NAME_LEN];
static struct sockaddr_ll raw_sockaddr;
static socklen_t raw_socklen;
/*--------------------------------------------------------------------------*/
static int rx_from_raw(void *ptr, int llid, int fd);
static void err_raw (void *ptr, int llid, int err, int from);
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int get_intf_ifindex(t_all_ctx *all_ctx, char *name)
{
  int result = -1, s, io;
  struct ifreq ifr;
  s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (s <= 0)
    KERR("Error %s line %d errno %d\n",__FUNCTION__,__LINE__,errno);
  else
    {
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, name, IFNAMSIZ);
    io = ioctl (s, SIOCGIFINDEX, &ifr);
    if(io != 0)
      KERR("Error %s line %d errno %d\n",__FUNCTION__,__LINE__,errno);
    else
      {
      glob_ifindex = ifr.ifr_ifindex;
      io = ioctl (s, SIOCGIFFLAGS, &ifr);
      if(io != 0)
        KERR("Error %s line %d errno %d\n",__FUNCTION__,__LINE__,errno);
      else
        {
        ifr.ifr_flags |= IFF_PROMISC;
        io = ioctl(s, SIOCSIFFLAGS, &ifr);
        if(io != 0)
          KERR("Error %s line %d errno %d\n",__FUNCTION__,__LINE__,errno);
        else
          result = 0;
        }
      }
    close(s);
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int raw_socket_open(t_all_ctx *all_ctx)
{
  int result = 0;
  if (g_llid_raw)
    KOUT(" ");
  result = get_intf_ifindex(all_ctx, g_raw_name);
  if (!result)
    {
    g_fd_raw = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if ((g_fd_raw < 0) || (g_fd_raw >= MAX_SELECT_CHANNELS-1))
      KOUT("%d", g_fd_raw);
    g_llid_raw = msg_watch_fd(all_ctx, g_fd_raw, rx_from_raw, err_raw);
    nonblock_fd(g_fd_raw);
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void init_raw_sockaddr(int is_tx)
{
  memset(&raw_sockaddr, 0, sizeof(struct sockaddr_ll));
  raw_sockaddr.sll_family = htons(PF_PACKET);
  raw_sockaddr.sll_protocol = htons(ETH_P_ALL);
  raw_sockaddr.sll_halen = 6;
  raw_sockaddr.sll_ifindex = glob_ifindex;
  raw_socklen = sizeof(struct sockaddr_ll);
  if (is_tx)
    raw_sockaddr.sll_pkttype = PACKET_OUTGOING;
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
void raw_fd_tx(t_all_ctx *all_ctx, t_blkd *blkd)
{
  int len, fd;
  fd = get_fd_with_llid(all_ctx, g_llid_raw);
  if (fd < 0)
   KOUT(" ");
  else if (g_fd_raw != fd)
    KOUT("%d %d", g_fd_raw, fd);
  else
    {
    init_raw_sockaddr(1);
    len = sendto(fd, blkd->payload_blkd, blkd->payload_len, 0,
                    (struct sockaddr *)&(raw_sockaddr),
                    raw_socklen);
    if(blkd->payload_len != len)
      KERR("%d %d", blkd->payload_len, len);
    }
  blkd_free((void *)all_ctx, blkd);
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static void err_raw (void *ptr, int llid, int err, int from)
{
  int is_blkd;
  t_all_ctx *all_ctx = (t_all_ctx *) ptr;
  if (msg_exist_channel(all_ctx, llid, &is_blkd, __FUNCTION__))
    msg_delete_channel(all_ctx, llid);
  if (llid == g_llid_raw)
    {
    KERR(" ");
    g_llid_raw = 0;
    }
  else
    KOUT("%d %d", llid, g_llid_raw);
}
/*-------------------------------------------------------------------------*/

/****************************************************************************/
static int rx_from_raw(void *ptr, int llid, int fd)
{
  t_all_ctx *all_ctx = (t_all_ctx *) ptr;
  t_blkd *bd;
  char *data;
  int len;
  init_raw_sockaddr(0);

  bd = blkd_create_tx_empty(0,0,0);
  data = bd->payload_blkd;
  len = recvfrom(fd, data, PAYLOAD_BLKD_SIZE, 0, 
                 (struct sockaddr *)&(raw_sockaddr), &raw_socklen);
  while(1)
    {
    if (len == 0)
      KOUT(" ");
    if (len < 0)
      {
      if ((errno == EAGAIN) || (errno ==EINTR))
        len = 0;
      else
        KOUT("%d ", errno);
      blkd_free(ptr, bd);
      break;
      }
    else 
      {
      if ((raw_sockaddr.sll_pkttype != PACKET_OUTGOING) &&
          (raw_sockaddr.sll_ifindex == glob_ifindex))
        {
        if (llid != g_llid_raw)
          KOUT(" ");
        bd->payload_len = len;
        sock_fd_tx(all_ctx, 0, bd);
        }
      else
        blkd_free(ptr, bd);
      bd = blkd_create_tx_empty(0,0,0);
      data = bd->payload_blkd;
      len = recvfrom(fd, data, PAYLOAD_BLKD_SIZE, 0, 
                     (struct sockaddr *)&(raw_sockaddr), &raw_socklen);
      }
    }
  return len;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int  raw_fd_open(t_all_ctx *all_ctx, char *name)
{ 
  int result = -1;
  strncpy(g_raw_name, name, MAX_NAME_LEN-1);
  if (!raw_socket_open(all_ctx))
    result = 0;
  else
    KERR("%s", name);
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void raw_fd_init(t_all_ctx *all_ctx)
{
  glob_ifindex = 0;
  g_llid_raw = 0;
  memset(g_raw_name, 0, MAX_NAME_LEN);
  memset(&raw_sockaddr, 0, sizeof(struct sockaddr_ll));
  raw_socklen = 0;
  g_fd_raw = -1;
}
/*---------------------------------------------------------------------------*/
