/*****************************************************************************/
/*    Copyright (C) 2006-2017 cloonix@cloonix.net License AGPL-3             */
/*                                                                           */
/*  This program is free software: you can redistribute it and/or modify     */
/*  it under the terms of the GNU Affero General Public License as           */
/*  published by the Free Software Foundation, either version 3 of the       */
/*  License, or (at your option) any later version.                          */
/*                                                                           */
/*  This program is distributed in the hope that it will be useful,          */
/*  but WITHOUT ANY WARRANTY; without even the implied warranty of           */
/*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            */
/*  GNU Affero General Public License for more details.a                     */
/*                                                                           */
/*  You should have received a copy of the GNU Affero General Public License */
/*  along with this program.  If not, see <http://www.gnu.org/licenses/>.    */
/*                                                                           */
/*****************************************************************************/
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/un.h>

#include "ioc.h"
#include "clo_tcp.h"
#include "sock_fd.h"
#include "main.h"
#include "machine.h"
#include "utils.h"
#include "bootp_input.h"
#include "packets_io.h"

#define RFC1533_COOKIE          99, 130, 83, 99
#define RFC1533_PAD             0
#define RFC1533_END             255
#define RFC2132_MSG_TYPE        53
#define RFC2132_REQ_ADDR        50
#define RFC2132_LEASE_TIME      51
#define RFC1533_DNS             6
#define RFC1533_GATEWAY         3
#define RFC1533_END             255
#define RFC2132_SRV_ID          54
#define RFC1533_NETMASK         1


#define LEASE_TIME (0xFFFFF)
#define DHCPDISCOVER            1
#define DHCPOFFER               2
#define DHCPREQUEST             3
#define DHCPACK                 5
#define DHCPNACK                6

typedef struct t_eth_mac
{
  char mac[MAX_NAME_LEN];  
} t_eth_mac;

typedef struct t_stored_mac
{
  char name[MAX_NAME_LEN];
  int vm_id;
  t_eth_mac eth[MAX_ETH_VM];
  struct t_stored_mac *prev;
  struct t_stored_mac *next;
} t_stored_mac;

typedef struct t_active_mac
{
  char name[MAX_NAME_LEN];
  char mac[MAX_NAME_LEN];  
  struct t_active_mac *prev;
  struct t_active_mac *next;
} t_active_mac;

struct bootp_t {
    char  bp_op;
    char  bp_htype;
    char  bp_hlen;
    char  bp_hops;
    int   bp_xid;
    short bp_secs;
    short unused;
    int   bp_ciaddr;
    int   bp_yiaddr;
    int   bp_siaddr;
    int   bp_giaddr;
    char  bp_hwaddr[16];
    char  bp_sname[64];
    char  bp_file[128];
    char  bp_vend[DHCP_OPT_LEN];
};

static char rfc1533_cookie[] = { RFC1533_COOKIE };

static t_stored_mac *g_stored_mac_head;
static t_active_mac *g_active_mac_head;


/*****************************************************************************/
static t_active_mac *find_active_with_mac(char *mac)
{
  t_active_mac *cur = g_active_mac_head;
  while(cur && (strcmp(cur->mac, mac)))
    cur = cur->next;
  return cur;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static t_active_mac *find_active_with_name(char *name)
{
  t_active_mac *cur = g_active_mac_head;
  while(cur && (strcmp(cur->name, name)))
    cur = cur->next;
  return cur;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static t_active_mac *alloc_active_mac(char *name, char *mac)
{
  t_active_mac *cur;
  cur = (t_active_mac *) malloc(sizeof(t_active_mac));
  memset(cur, 0, sizeof(t_active_mac));
  strncpy(cur->name, name, MAX_NAME_LEN-1);
  strncpy(cur->mac, mac, MAX_NAME_LEN-1);
  if (g_active_mac_head)
    g_active_mac_head->prev = cur;
  cur->next = g_active_mac_head;
  g_active_mac_head = cur;
  return cur;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void free_active_mac(t_active_mac *cur)
{
  if (cur->prev)
    cur->prev->next = cur->next;
  if (cur->next)
    cur->next->prev = cur->prev;
  if (g_active_mac_head == cur)
    g_active_mac_head = cur->next;
  free(cur);
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
static t_stored_mac *find_mac_in_stored_mac(char *mac)
{
  int i;
  t_stored_mac *cur = g_stored_mac_head;
  t_stored_mac *result = NULL;
  while(cur)
    {
    for (i=0; i<MAX_ETH_VM; i++)
      {
      if (!strcmp(cur->eth[i].mac, mac))
        {
        result = cur;
        break;
        }
      }
    if (result)
      break;
    cur = cur->next;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static t_stored_mac *find_stored_mac(char *name, int vm_id)
{
  t_stored_mac *cur = g_stored_mac_head;
  while(cur && (strcmp(cur->name, name)) && (vm_id != cur->vm_id))
    cur = cur->next;
  return cur;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static t_stored_mac *alloc_stored_mac(char *name, int vm_id)
{
  t_stored_mac *cur;
  cur = (t_stored_mac *) malloc(sizeof(t_stored_mac));
  memset(cur, 0, sizeof(t_stored_mac));
  strncpy(cur->name, name, MAX_NAME_LEN-1);
  cur->vm_id = vm_id;
  if (g_stored_mac_head)
    g_stored_mac_head->prev = cur;
  cur->next = g_stored_mac_head;
  g_stored_mac_head = cur;
  add_machine(name, vm_id);
  return cur;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void free_stored_mac(t_stored_mac *cur)
{
  if (cur->prev)
    cur->prev->next = cur->next;
  if (cur->next)
    cur->next->prev = cur->prev;
  if (g_stored_mac_head == cur)
    g_stored_mac_head = cur->next;
  del_machine(cur->name, cur->vm_id);
  free(cur);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
char *get_mac_with_name(char *name)
{
  char *result = NULL;
  t_active_mac *act = find_active_with_name(name);
  if (act)
    result = act->mac;
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
char *get_name_with_mac(char *mac)
{
  t_stored_mac *cur;
  char *result = NULL;
  t_active_mac *act = find_active_with_mac(mac);
  if (act)
    result = act->name;
  else
    {
    cur = find_mac_in_stored_mac(mac);
    if (cur)
      result = cur->name;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int get_dhcp_addr(uint32_t *addr, char *mac)
{
  uint32_t our_ip_gw;
  int result = -1;
  t_active_mac *act;
  t_stored_mac *cur = find_mac_in_stored_mac(mac);
  if (!cur)
    KERR("BAD MAC ADDRESS %s", mac);
  else
    {
    act = find_active_with_name(cur->name);
    if (act)
      free_active_mac(act);
    alloc_active_mac(cur->name, mac);
    if (ip_string_to_int (&our_ip_gw, get_gw_ip()))
      KOUT(" ");
    *addr = our_ip_gw + cur->vm_id + 2; 
    result = 0;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void dhcp_decode(int len, char *data, int *type, uint32_t *addr)
{
  char *p, *p_end;
  int lng, tag;
  *type = 0;
  *addr = 0;
  p = data;
  p_end = data + len;
  if ((len >= 5) && (memcmp(p, rfc1533_cookie, 4) == 0))
    {
    p += 4;
    while (p < p_end)
      {
      tag = p[0];
      if (tag == RFC1533_PAD)
        p++;
      else if (tag == RFC1533_END)
        break;
      else
        {
        p++;
        if (p >= p_end)
          break;
        lng = *p++;
        lng &= 0xFF;
        switch(tag)
          {
          case RFC2132_MSG_TYPE:
            if (lng >= 1)
              *type = p[0] & 0xFF;
            break;
          case RFC2132_REQ_ADDR:
            if (lng == 4)
              {
              *addr += (p[0]<<24) & 0xFF;
              *addr += (p[1]<<16) & 0xFF;
              *addr += (p[2]<<8 ) & 0xFF;
              *addr += p[3] & 0xFF;
              }
            break;
          default:
            break;
          }
        p += lng;
        }
      }
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int format_rbp(struct bootp_t *bp, struct bootp_t *rbp, 
                      uint32_t addr, int type)
{
  uint32_t our_ip_gw, our_ip_dns, our_default_route;
  int len;
  char *q;
  if (ip_string_to_int (&our_ip_gw, get_gw_ip()))
    KOUT(" ");
  if (ip_string_to_int (&our_default_route, get_gw_ip()))
    KOUT(" ");
  if (ip_string_to_int (&our_ip_dns, get_dns_ip()))
    KOUT(" ");
  rbp->bp_op = BOOTP_REPLY;
  rbp->bp_xid = bp->bp_xid;
  rbp->bp_htype = 1;
  rbp->bp_hlen = 6;
  memcpy(rbp->bp_hwaddr, bp->bp_hwaddr, 6);
  rbp->bp_yiaddr = htonl(addr);
  rbp->bp_siaddr = htonl(our_ip_gw);
  strcpy(rbp->bp_sname, "slirpserverhost");
  strcpy(rbp->bp_file, "boot_file_name");
  q = rbp->bp_vend;
  memcpy(q, rfc1533_cookie, 4);
  q += 4;
  *q++ = RFC2132_MSG_TYPE;
  *q++ = 1;
  *q++ = (type==DHCPDISCOVER)?DHCPOFFER:DHCPACK;
  *q++ = RFC2132_SRV_ID;
  *q++ = 4;
  *q++ = (our_ip_gw >> 24) & 0xFF;
  *q++ = (our_ip_gw >> 16) & 0xFF;
  *q++ = (our_ip_gw >> 8) & 0xFF;
  *q++ = our_ip_gw & 0xFF;
  *q++ = RFC1533_NETMASK;
  *q++ = 4;
  *q++ = 0xff;
  *q++ = 0xff;
  *q++ = 0xff;
  *q++ = 0x00;
  *q++ = RFC1533_GATEWAY;
  *q++ = 4;
  *q++ = (our_default_route >> 24) & 0xFF;
  *q++ = (our_default_route >> 16) & 0xFF;
  *q++ = (our_default_route >> 8) & 0xFF;
  *q++ = our_default_route & 0xFF;
  *q++ = RFC1533_DNS;
  *q++ = 4;
  *q++ = (our_ip_dns >> 24) & 0xFF;
  *q++ = (our_ip_dns >> 16) & 0xFF;
  *q++ = (our_ip_dns >> 8) & 0xFF;
  *q++ = our_ip_dns & 0xFF;
  *q++ = RFC2132_LEASE_TIME;
  *q++ = 4;
  *q++ = (LEASE_TIME >> 24) & 0xFF;
  *q++ = (LEASE_TIME >> 16) & 0xFF;
  *q++ = (LEASE_TIME >> 8) & 0xFF;
  *q++ = LEASE_TIME & 0xFF;
  *q++ = RFC1533_END;
  len = q - (char *) rbp;
  return len;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int bootp_format_reply(int len, uint32_t *addr,
                              struct bootp_t *bp, struct bootp_t *rbp)
{
  int result = -1;
  int type;
  char mac[MAX_NAME_LEN];
  char *mc;
  dhcp_decode(len, bp->bp_vend, &type, addr);
  if ((type == DHCPDISCOVER) || (type == DHCPREQUEST)) 
    {
    mc = bp->bp_hwaddr;
    sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
                  mc[0]&0xFF, mc[1]&0xFF, mc[2]&0xFF,
                  mc[3]&0xFF, mc[4]&0xFF, mc[5]&0xFF);
    if (!get_dhcp_addr(addr, mac))
      result =  format_rbp(bp, rbp, *addr, type);
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void packet_bootp_input(t_machine *machine, char *src_mac, char *dst_mac,
                        int len, char *data)
{
  char alloc_ip[MAX_NAME_LEN];
  struct bootp_t *bp = (struct bootp_t *)data;
  static char resp[MAC_HEADER+IP_HEADER+UDP_HEADER+sizeof(struct bootp_t)];
  uint32_t addr;
  int resp_len;
  struct bootp_t *rbp;
  rbp = (struct bootp_t *) &(resp[MAC_HEADER+IP_HEADER+UDP_HEADER]); 
  if (bp->bp_op == BOOTP_REQUEST)
    {
    resp_len = bootp_format_reply(len, &addr, bp, rbp);
    if ((resp_len > 0) && addr)
      {
      int_to_ip_string (addr, alloc_ip);
      machine_boop_alloc(machine, alloc_ip);
      fill_mac_ip_header(resp, get_gw_ip(), src_mac);
      fill_ip_ip_header((IP_HEADER + UDP_HEADER + resp_len), 
                         &(resp[MAC_HEADER]), 
                         get_gw_ip(),"255.255.255.255", IPPROTO_UDP);
      fill_udp_ip_header((UDP_HEADER + resp_len), 
                          &(resp[MAC_HEADER+IP_HEADER]), 
                          BOOTP_SERVER, BOOTP_CLIENT);
      resp_len += MAC_HEADER + IP_HEADER + UDP_HEADER; 
      packet_output_to_slirptux(resp_len, resp);
      }
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void set_dhcp_addr(char *name, int vm_id, int num, char *mac)
{
  t_stored_mac *cur = find_stored_mac(name, vm_id);
  if (!cur)
    cur = alloc_stored_mac(name, vm_id);
  if ((num >= 0) && (num < MAX_ETH_VM))
    {
    memset(cur->eth[num].mac, 0, MAX_NAME_LEN);
    strncpy(cur->eth[num].mac, mac, MAX_NAME_LEN-1);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void unset_dhcp_addr(char *name, int vm_id, int num, char *mac)
{
  int i, can_free;
  t_stored_mac *cur = find_stored_mac(name, vm_id);
  t_active_mac *act = find_active_with_mac(mac);
  if (act)
    free_active_mac(act);
  if (cur)
    {
    if ((num >= 0) && (num < MAX_ETH_VM))
      {
      if (strcmp(cur->eth[num].mac, mac))
        KERR("%s %d %d %s %s", name, vm_id, num, mac, cur->eth[num].mac);
      memset(cur->eth[num].mac, 0, MAX_NAME_LEN);
      }
    can_free = 1;
    for (i=0; i<MAX_ETH_VM; i++)
      {
      if (strlen(cur->eth[i].mac))
        can_free = 0;
      }
    if (can_free)
      {
      free_stored_mac(cur);
      }
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void init_bootp(void)
{
  g_stored_mac_head = NULL;
  g_active_mac_head = NULL;
}
/*---------------------------------------------------------------------------*/
