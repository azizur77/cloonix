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


#define TOTAL_LOSS_VALUE   10000 

/****************************************************************************/
typedef struct t_queue
{
  t_blkd *blkd;
  long long arrival_date_us;
  struct t_queue *next;
} t_queue;
/*--------------------------------------------------------------------------*/
typedef struct t_qctx
{
  t_queue *head;
  t_queue *tail;
} t_qctx;
/*--------------------------------------------------------------------------*/
static t_qctx Actx;
static t_qctx Bctx;
static long long g_prev_date_us;
static t_all_ctx *g_all_ctx;

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
static int tocken_authorization(t_connect_side *side, int len)
{
  int result = 0;
  if (side->qstats.tockens > len)
    result = 1;
  return result;
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static void update_remove_tockens(t_connect_side *side, int len)
{
  side->tockens_1000 -= (len * 1000);
  if (side->tockens_1000 < 0)
    KOUT("%d   %d",  side->tockens_1000, len);
  side->qstats.tockens = side->tockens_1000/1000;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void update_add_tockens(t_connect_side *side, int ms_delta)
{
  int conf_bsize_1000 = 1000 * side->qstats.conf_bsize;
  side->tockens_1000 += side->qstats.conf_brate * ms_delta;
  if (side->tockens_1000 > conf_bsize_1000)
    side->tockens_1000 = conf_bsize_1000;
  side->qstats.tockens = side->tockens_1000/1000;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int sum_samples(int *tab, int *msec, int index0, int nb_samples)
{
  int i, j;
  long long result = 0;
  long long sum_delta = 0;
  for (i=1; i<nb_samples+1; i++)
    {
    j = index0 - i;
    if (j < 0)
      j += MAX_SAMPLES;
    result += tab[j]; 
    sum_delta += msec[j]; 
    }
  if (sum_delta)
    {
    result *= 1000;
    result /= sum_delta;
    }
  else
    result = 0;
  return ((int) result);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int get_samply_nb(int index0, int last_index0)
{
  int result;
  if ((index0 < 0) || (index0 >= MAX_SAMPLES) ||
      (last_index0 < 0) || (last_index0 >= MAX_SAMPLES))
    KOUT("%d %d", index0, last_index0);
  if (index0 > last_index0)
    result = index0 - last_index0;
  else
    result = MAX_SAMPLES + index0 - last_index0;
  if (result == 0)
    KERR(" ");
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void samply(int *src, int *dst, int nb, int last_index0)
{
  int i, j;
  for (i=0; i<nb; i++)
    {
    j = last_index0 + i;
    if (j >= MAX_SAMPLES)
      j = 0;
    dst[i] = src[j];
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void update_stats(t_connect_side *side)
{
  int samply_nb;
  int index0 = side->samply_current; 
  int last_index0 = side->samply_last_sent; 
  side->qstats.sec_01_rate = sum_samples(side->samply_dequeue, 
                                         side->samply_msec, index0, 10);
  side->qstats.sec_10_rate = sum_samples(side->samply_dequeue, 
                                         side->samply_msec, index0, 100);
  side->qstats.sec_40_rate = sum_samples(side->samply_dequeue, 
                                         side->samply_msec, index0, 400);
  samply_nb = get_samply_nb(index0, last_index0);
  samply(side->samply_enqueue,
         side->qstats.samply_enqueue,samply_nb,last_index0);
  samply(side->samply_dequeue,
         side->qstats.samply_dequeue,samply_nb,last_index0);
  samply(side->samply_dropped,
         side->qstats.samply_dropped,samply_nb,last_index0);
  samply(side->samply_stored,
         side->qstats.samply_stored,samply_nb,last_index0);
  samply(side->samply_msec,side->qstats.samply_msec,
         samply_nb,last_index0);
  side->qstats.samply_nb = samply_nb;
  side->samply_last_sent = side->samply_current; 
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_connect_side *init_ctx(int a0_b1, t_queue ***head, t_queue ***tail)
{
  t_connect_side *side;
  if (a0_b1 == 0)
    {
    side = get_sideA();
    *head = &(Actx.head);
    *tail = &(Actx.tail);
    }
  else if (a0_b1 == 1)
    {
    side = get_sideB();
    *head = &(Bctx.head);
    *tail = &(Bctx.tail);
    }
  else
    KOUT(" ");
  return side;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void inc_queue_size(t_connect_side *side, int len)
{
  side->qstats.enqueue += len;
  side->qstats.stored += len;
  side->samply_stored[side->samply_current] = side->qstats.stored;
  side->samply_enqueue[side->samply_current] += len;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void dec_queue_size(t_connect_side *side, int len)
{
  side->qstats.dequeue += len;
  side->qstats.stored -= len;
  side->samply_stored[side->samply_current] = side->qstats.stored;
  side->samply_dequeue[side->samply_current] += len;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static int is_lost(int loss)
{
  int cmp_loss, lost_pkt = 0;
  if (loss)
    {
    cmp_loss = rand()%TOTAL_LOSS_VALUE;
    if (cmp_loss <= loss)
      lost_pkt = 1;
    }
  return lost_pkt;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int can_enqueue(int a0_b1, int len)
{
  int result = 0;
  t_connect_side *side;
  if (a0_b1 == 0)
    side = get_sideA();
  else if (a0_b1 == 1)
    side = get_sideB();
  else
    KOUT(" ");
  if (is_lost(side->qstats.conf_loss))
    side->qstats.lost += len;
  else
    {
    if (side->qstats.stored + len < side->qstats.conf_qsize)
      result = 1;
    else
      {
      side->qstats.dropped += len;
      side->samply_dropped[side->samply_current] += len;
      }
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static void do_enqueue(int a0_b1,  t_blkd *blkd, long long now)
{
  t_queue *q = (t_queue *) malloc(sizeof(t_queue));
  t_queue **head;
  t_queue **tail;
  t_connect_side *side;
  side = init_ctx(a0_b1, &head, &tail);
  memset(q, 0, sizeof(t_queue));
  q->arrival_date_us = now;
  q->blkd = blkd;
  if (*head)
    {
    if (((*tail)==NULL) || ((*tail)->next!=NULL))
      KOUT(" ");
    (*tail)->next = q;
    (*tail) = q;
    }
  else
    {
    if (*tail)
      KOUT(" ");
    (*head) = q;
    (*tail) = q;
    }
  inc_queue_size(side, blkd->payload_len);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int action_dequeue_if_ok(t_connect_side *side, t_queue *q,
                                t_queue **head, t_queue **tail, int len)
{ 
  int result = -1;
  if (tocken_authorization(side, len))
    {
    if ((*head) == (*tail))
      {
      (*head) = NULL;
      (*tail) = NULL;
      }
    else
      *head = q->next;
    free(q);
    dec_queue_size(side, len);
    update_remove_tockens(side, len);
    result = 0;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static t_blkd *do_dequeue(int a0_b1, long long now, t_connect_side **side)
{
  t_blkd *result = NULL;
  t_blkd *blkd;
  int delta;
  t_queue *q;
  t_queue **head;
  t_queue **tail;
  *side = init_ctx(a0_b1, &head, &tail);
  if (*head)
    {
    blkd = (*head)->blkd;
    q = (*head);
    delta = (int) (now - q->arrival_date_us);
    delta /= 1000;
    if (delta >= (*side)->qstats.conf_delay)
      { 
      if (!action_dequeue_if_ok((*side), q, head, tail, blkd->payload_len))
        result = blkd;
      }
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void sched_tx(int a0_b1, long long now) 
{
  t_connect_side *side;
  t_blkd *blkd;
  blkd = do_dequeue(a0_b1, now, &side);
  while(blkd)
    {
    sock_fd_tx(g_all_ctx, blkd);
    blkd = do_dequeue(a0_b1, now, &side);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void timer_sched_side(int a0_b1, t_connect_side *side, int ms_delta,
                             long long now, int inc_sample)
{
  side->samply_stored[side->samply_current] = side->qstats.stored;
  update_add_tockens(side, ms_delta);
  side->samply_msec[side->samply_current] += ms_delta;
  sched_tx(a0_b1, now);
  if (inc_sample)
    {
    side->samply_current += 1;
    if (side->samply_current == MAX_SAMPLES)
      side->samply_current = 0;
    side->samply_enqueue[side->samply_current] = 0;
    side->samply_dequeue[side->samply_current] = 0;
    side->samply_stored[side->samply_current] = 0;
    side->samply_dropped[side->samply_current] = 0;
    side->samply_msec[side->samply_current] = 0;
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void timer_sched(long delta_ns, void *data)
{
  static int count_100ms = 0;
  int delta, ms_delta, inc_sample;
  long long date_us;
  long long now_date_us = get_target_date_us();
  t_connect_side *side;
  count_100ms += 1;
  if (count_100ms == 100)
    {
    count_100ms = 0;
    inc_sample = 1;
    }
  else
    inc_sample = 0;
  delta = (int) (now_date_us - g_prev_date_us);
  ms_delta = delta/1000;

  side = get_sideA();
  timer_sched_side(0, side, ms_delta, now_date_us, inc_sample); 

  side = get_sideB();
  timer_sched_side(1, side, ms_delta, now_date_us, inc_sample); 

  if (clownix_real_timeout_add(1000, timer_sched, NULL, &date_us)) 
    KOUT(" ");
  g_prev_date_us = now_date_us;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void sched_update_stats(void)
{
  t_connect_side *side;
  side = get_sideA();
  update_stats(side);
  side = get_sideB();
  update_stats(side);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void sched_tx_pkt(int a0_b1, t_blkd *blkd) 
{
  long long now_date_us = get_target_date_us();
  if (can_enqueue(a0_b1, blkd->payload_len))
    {
    do_enqueue(a0_b1, blkd, now_date_us);
    }
  sched_tx(a0_b1, now_date_us);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void sched_qstats_zero(void)
{
  t_connect_side *side;
  side = get_sideA();
  side->qstats.enqueue = 0;
  side->qstats.dequeue = 0;
  side->qstats.dropped = 0;
  side->qstats.lost    = 0;
  side = get_sideB();
  side->qstats.enqueue = 0; 
  side->qstats.dequeue = 0;
  side->qstats.dropped = 0; 
  side->qstats.lost    = 0;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void shed_init(t_all_ctx *all_ctx)
{
  long long date_us;
  g_all_ctx = all_ctx;
  g_prev_date_us = get_target_date_us();
  if (clownix_real_timeout_add(1000, timer_sched, NULL, &date_us)) 
    KOUT(" ");
}
/*---------------------------------------------------------------------------*/

