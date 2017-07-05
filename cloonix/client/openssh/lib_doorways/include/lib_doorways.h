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
typedef void (*t_beat_time)(void);
typedef void (*t_rx_cb)(int len, char *buf);
char *get_full_bin_path(char *input_callbin);
int get_ip_port_from_path(char *param, int *ip, int *port);
void doorways_access_tx(int len, char *buf);
void doorways_access_init(char *cloonix_doors, char *cloonix_passwd,
                          char *address_in_vm, t_beat_time beat, t_rx_cb rx);
void doorways_access_loop(void);
/*--------------------------------------------------------------------------*/

