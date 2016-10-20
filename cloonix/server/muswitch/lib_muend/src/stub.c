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
#include <stdint.h>
#include <sys/types.h>


#include "ioc.h"

void linker_helper1_fct(void)
{
printf("useless");
}

/*****************************************************************************/
void rpct_recv_pid_resp(void *ptr,int llid,int tid,char *name,int pid){KOUT(" ");}
void rpct_recv_hop_msg(void *ptr, int llid, int tid, int flags_hop, char *txt){KOUT(" ");}
void rpct_recv_cli_resp(void *ptr,int llid,int tid,int cllid,int ctid,char *line){KOUT(" ");}
void rpct_recv_report(void *ptr, int llid, t_blkd_item *item){KOUT(" ");}
/*---------------------------------------------------------------------------*/




