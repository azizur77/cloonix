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
void receive_traf_x11_from_client(int dido_llid, int sub_dido_idx, 
                                  int len, char *buf);

void receive_ctrl_x11_from_client(int dido_llid, int doors_val,
                                  int len, char *buf);

void x11_open_close (int backdoor_llid, int dido_llid, char *rx_payload);
void x11_write(int dido_llid, int sub_dido_idx, int len, char *buf);
void x11_close(int backdoor_llid, int dido_llid);
void x11_init(void);
/*--------------------------------------------------------------------------*/


