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
#include <linux/sockios.h>



#include "ioc.h"
#include "tun_tap.h"
#include "sock_fd.h"

/*--------------------------------------------------------------------------*/
static int glob_ifindex;
static int g_llid_raw;
static int g_fd_raw;
static int g_fd_raw_tx;
static char g_raw_name[MAX_NAME_LEN];
static struct sockaddr_ll g_raw_sockaddr_rx;
static struct sockaddr_ll g_raw_sockaddr_tx;
static socklen_t g_raw_socklen_rx;
static socklen_t g_raw_socklen_tx;
/*--------------------------------------------------------------------------*/
static int rx_from_raw(void *ptr, int llid, int fd);
static void err_raw (void *ptr, int llid, int err, int from);
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void init_raw_sockaddr(int is_tx)
{
  if (is_tx)
    {
    memset(&g_raw_sockaddr_tx, 0, sizeof(struct sockaddr_ll));
    g_raw_sockaddr_tx.sll_family = AF_PACKET;
    g_raw_sockaddr_tx.sll_protocol = htons(ETH_P_ALL);
    g_raw_sockaddr_tx.sll_ifindex = glob_ifindex;
    g_raw_sockaddr_tx.sll_pkttype = PACKET_OUTGOING;
    g_raw_socklen_tx = sizeof(struct sockaddr_ll);
    }
  else
    {
    memset(&g_raw_sockaddr_rx, 0, sizeof(struct sockaddr_ll));
    g_raw_sockaddr_rx.sll_family = AF_PACKET;
    g_raw_sockaddr_rx.sll_protocol = htons(ETH_P_ALL);
    g_raw_sockaddr_rx.sll_ifindex = glob_ifindex;
    g_raw_sockaddr_rx.sll_pkttype = PACKET_HOST;
    g_raw_socklen_rx = sizeof(struct sockaddr_ll);
    }
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static int bind_raw_sock(int fd)
{
  int result;
  init_raw_sockaddr(0);
  result = bind(fd, (struct sockaddr*) &g_raw_sockaddr_rx, g_raw_socklen_rx); 
  return result;
}
/*---------------------------------------------------------------------------*/

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
    g_fd_raw_tx = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    g_fd_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (g_fd_raw_tx < 0)
      KOUT("%d %d", g_fd_raw_tx, errno);
    if ((g_fd_raw < 0) || (g_fd_raw >= MAX_SELECT_CHANNELS-1))
      KOUT("%d %d", g_fd_raw, errno);
    if (bind_raw_sock(g_fd_raw))
      KOUT("%d %d", g_fd_raw, errno);
    if (bind_raw_sock(g_fd_raw_tx))
      KOUT("%d %d", g_fd_raw_tx, errno);
    g_llid_raw = msg_watch_fd(all_ctx, g_fd_raw, rx_from_raw, err_raw);
    nonblock_fd(g_fd_raw);
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void raw_fd_tx(t_all_ctx *all_ctx, t_blkd *blkd)
{
  int len;
  init_raw_sockaddr(1);
  len = sendto(g_fd_raw_tx, blkd->payload_blkd, blkd->payload_len, 0,
              (struct sockaddr *)&(g_raw_sockaddr_tx), g_raw_socklen_tx);
  if(blkd->payload_len != len)
    KERR("%d %d", blkd->payload_len, len);
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


/*****************************************************************************/
static int is_an_ip_packet(char *data)
{ 
  int result = 0;
  if ((data[12] == 0x08) && 
      (data[13] == 0x00) &&
      (data[14] == 0x45))
    result = 1;
  return result;
}
/*---------------------------------------------------------------------------*/


/*
void my_ip_seg(void)
{
  struct ip_hdr *iphdr;
  memcpy(iphdr, p->payload, IP_HLEN);

  tmp = ntohs(IPH_OFFSET(iphdr));
  ofo = tmp & IP_OFFMASK;
  omf = tmp & IP_MF;



  left = p->tot_len - IP_HLEN;

  while (left) {
    last = (left <= mtu - IP_HLEN);

    ofo += nfb;
    tmp = omf | (IP_OFFMASK & (ofo));
    if (!last)
      tmp = tmp | IP_MF;
    IPH_OFFSET_SET(iphdr, htons(tmp));

    nfb = (mtu - IP_HLEN) / 8;
    cop = last ? left : nfb * 8;
    p = copy_from_pbuf(p, &poff, (u8_t *) iphdr + IP_HLEN, cop);

    IPH_LEN_SET(iphdr, htons(cop + IP_HLEN));
    IPH_CHKSUM_SET(iphdr, 0);
    IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, IP_HLEN));

    if (last)
      pbuf_realloc(rambuf, left + IP_HLEN);
    header = pbuf_alloc(PBUF_LINK, 0, PBUF_RAM);
    if (header != NULL) {
      pbuf_chain(header, rambuf);
      netif->output(netif, header, dest);
      IPFRAG_STATS_INC(ip_frag.xmit);
      pbuf_free(header);
    } else {
      pbuf_free(rambuf);
      return ERR_MEM;
    }
    left -= cop;
  }
*/

/****************************************************************************/
static void ip_fragmentation_tx(t_all_ctx *all_ctx, int len, 
                                char *buf, t_blkd *first_bd)
{
  t_blkd *bd = first_bd;
  char *data = bd->payload_blkd;
  int i, nb_64_blocks = 22;
  int nb_oct_per_frag = nb_64_blocks*64;
  int div = len/nb_oct_per_frag;
  int left = len%nb_oct_per_frag;
  int tot_head = 12 + 2 + 20;
  if (left == 0)
    {
    if (div <= 0)
      KOUT("%d", div);
    div -= 1;
    left = nb_oct_per_frag;
    }
  for (i = 0; i < div; i++)
    {
    memcpy(data, buf, tot_head);
    memcpy(data + tot_head, buf+(i*nb_oct_per_frag), nb_oct_per_frag);
    bd->payload_len = nb_oct_per_frag + tot_head;
    sock_fd_tx(all_ctx, 0, bd);
    bd = blkd_create_tx_empty(0,0,0);
    data = bd->payload_blkd;
    }
  memcpy(data, buf, tot_head);
  memcpy(data + tot_head, buf+(i*nb_oct_per_frag), left);
  bd->payload_len = left;
  sock_fd_tx(all_ctx, 0, bd);
}
/*-------------------------------------------------------------------------*/


/****************************************************************************/
static int rx_from_raw(void *ptr, int llid, int fd)
{
  t_all_ctx *all_ctx = (t_all_ctx *) ptr;
  t_blkd *bd;
  char *data;
  char *tmpbuf = NULL;
  int len, queue_size;
  if (ioctl(fd, SIOCINQ, &queue_size))
    {
    KERR("DROP");
    return 0;
    }
  if (queue_size > PAYLOAD_BLKD_SIZE)
    tmpbuf = (char *) malloc(queue_size);
  bd = blkd_create_tx_empty(0,0,0);
  data = bd->payload_blkd;
  init_raw_sockaddr(0);
  if (tmpbuf == NULL)
    {
    len = recvfrom(fd, data, PAYLOAD_BLKD_SIZE, 0, 
                   (struct sockaddr *)&(g_raw_sockaddr_rx),
                   &g_raw_socklen_rx);
    if (len == 0)
      KOUT(" ");
    }
  else
    {
    len = recvfrom(fd, tmpbuf, queue_size, 0,  
                   (struct sockaddr *)&(g_raw_sockaddr_rx),
                   &g_raw_socklen_rx);
    if (len == 0)
      KOUT(" ");
    if ((len != queue_size) || (!is_an_ip_packet(tmpbuf)))
      {
      KERR("len: %d size:%d Limit:%d", len, queue_size, PAYLOAD_BLKD_SIZE);
      blkd_free(ptr, bd);
      len = 0;
      }
    }
  if (len < 0)
    {
    if ((errno == EAGAIN) || (errno ==EINTR))
      len = 0;
    else
      KOUT("%d ", errno);
    blkd_free(ptr, bd);
    KERR(" ");
    }
  else if (len > 0) 
    {
    if (((g_raw_sockaddr_rx.sll_pkttype != PACKET_HOST)      &&
         (g_raw_sockaddr_rx.sll_pkttype != PACKET_BROADCAST) &&
         (g_raw_sockaddr_rx.sll_pkttype != PACKET_MULTICAST) &&
         (g_raw_sockaddr_rx.sll_pkttype != PACKET_OTHERHOST)) ||
        (g_raw_sockaddr_rx.sll_ifindex != glob_ifindex))
      {
      blkd_free(ptr, bd);
      }
    else
      {
      if (tmpbuf == NULL)
        {
        bd->payload_len = len;
        sock_fd_tx(all_ctx, 0, bd);
        }
      else
        {
        ip_fragmentation_tx(all_ctx, len, tmpbuf, bd);
        }
      }
    }
  free(tmpbuf);
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
  g_fd_raw = -1;
  g_fd_raw_tx = -1;
}
/*---------------------------------------------------------------------------*/
