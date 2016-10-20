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
typedef struct t_eventfull
{
  int nb_vm;
  t_eventfull_vm *vm;
  int nb_sat;
  t_eventfull_sat *sat;
} t_eventfull;
/*---------------------------------------------------------------------------*/
void event_full_timeout_blink_off(void);
/*---------------------------------------------------------------------------*/
void eventfull_200_ms_packets_data(t_eventfull *eventfull);
/*---------------------------------------------------------------------------*/
void eventfull_node_create(char *name);
/*---------------------------------------------------------------------------*/
void eventfull_node_delete(char *name);
/*---------------------------------------------------------------------------*/
void eventfull_sat_create(char *name);
void eventfull_sat_delete(char *name);
/*---------------------------------------------------------------------------*/
void eventfull_init(void);
/*---------------------------------------------------------------------------*/

