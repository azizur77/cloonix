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
void sock_fd_local_flow_control(t_all_ctx *all_ctx, int stop);
void sock_fd_tx(t_all_ctx *all_ctx, int idx, t_blkd *blkd);
void rx_from_traffic_sock(t_all_ctx *all_ctx, int idx, t_blkd *bd);
int sock_fd_open(t_all_ctx *all_ctx, char *lan, int idx, char *sock_path);
void sock_fd_finish(t_all_ctx *all_ctx, int idx);
void sock_fd_init(t_all_ctx *all_ctx);
void rx0_blkd_sock_cb(void *ptr, int llid);
/*---------------------------------------------------------------------------*/


