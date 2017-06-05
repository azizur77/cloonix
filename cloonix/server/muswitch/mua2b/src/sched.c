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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#include "ioc.h"
#include "config.h"
#include "sock_fd.h"
#include "circ_slot.h"

/****************************************************************************/
typedef struct t_queue
{
  t_blkd *blkd;
  long long arrival_date_us;
  struct t_queue *next;
} t_queue;
/*--------------------------------------------------------------------------*/
static t_all_ctx *g_all_ctx0 = NULL;
static t_all_ctx *g_all_ctx1 = NULL;

static int g_tx0, g_tx1;

/*****************************************************************************/
static long long get_target_date_us(void)
{
  struct timespec ts;
  long long sec;
  long long nsec;
  long long result;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  sec = (long long) ts.tv_sec;
  sec *= 1000000;
  nsec = (long long) ts.tv_nsec;
  nsec /= 1000;
  result = sec + nsec;
  return result;
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static void do_enqueue(int num, long long now,  t_blkd *blkd)
{
  t_queue *q;
  int count = circ_empty_slot_nb(num);
  if (count > 0)
    {
    q = (t_queue *) malloc(sizeof(t_queue));
    memset(q, 0, sizeof(t_queue));
    q->arrival_date_us = now;
    q->blkd = blkd;
    circ_slot_put(num, (void *) q);
    }
  else
    KOUT("%d %d", num, count);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static t_blkd *do_dequeue(int num, long long now)
{
  t_blkd *result = NULL;
  t_queue *q;
  int count = circ_used_slot_nb(num);
  if (count)
    {
    q = (t_queue *) circ_slot_get(num);
    if (!q)
      KOUT("%d %d", num, count);
    result = q->blkd;
    free(q);    
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void activate_tx(int num, long long now)
{
  t_blkd *blkd;
  blkd = do_dequeue(num, now);
  while(blkd)
    {
    if (num == 0)
      {
      sock_fd_tx(g_all_ctx0, blkd);
      g_tx0 += 1;
      }
    else if (num == 1)
      {
      sock_fd_tx(g_all_ctx1, blkd);
      g_tx1 += 1;
      }
    else
      KOUT("%d", num);
    blkd = do_dequeue(num, now);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void timer_sched(long delta_ns, void *data)
{
  long long date_us;
  int num = (int)((unsigned long) data);
  if (clownix_real_timer_add(num, 1000, timer_sched, data, &date_us))
    KOUT(" ");
  activate_tx(num, date_us);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void sched_tx0_activate(t_all_ctx *all_ctx)
{
  long long now = get_target_date_us();
  activate_tx(0, now);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void sched_tx1_activate(t_all_ctx *all_ctx)
{
  long long now = get_target_date_us();
  activate_tx(1, now);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void sched_tx_pkt(int num, t_blkd *blkd) 
{
  long long now = get_target_date_us();
  do_enqueue(num, now, blkd);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void sched_get_g_tx(int *tx0, int *tx1)
{
  *tx0 = g_tx0;
  *tx1 = g_tx1;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void sched_init(int num, t_all_ctx *all_ctx)
{
  long long date_us;
  unsigned long data_num = (unsigned long) num;
  if (num == 0)
    g_all_ctx0 = all_ctx;
  else if (num == 1)
    g_all_ctx1 = all_ctx;
  else
    KOUT(" ");
  circ_slot_init(num);
  if (clownix_real_timer_add(num,1000,timer_sched,(void *)data_num,&date_us)) 
    KOUT(" ");
}
/*---------------------------------------------------------------------------*/

