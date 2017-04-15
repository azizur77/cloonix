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
int mueth_event_already_in_lan(char *vm_name, int vm_eth);
int mueth_event_lan_is_in_use(char *lan);

void mueth_event_admin_add_lan(int llid, int tid, 
                               char *vm_name, int vm_eth, char *lan);
int mueth_event_admin_del_lan(char *vm_name, int vm_eth, char *lan);

void mueth_event_mulan_birth(char *lan);
void mueth_event_mulan_death(char *lan);
void mueth_event_connect_OK(char *name, int eth, char *lan, int rank);
void mueth_event_connect_KO(char *name, int eth, char *lan);

void mueth_event_birth(char *vm_name,int vm_eth);
void mueth_event_death(char *vm_name,int vm_eth);
void mueth_event_timer_ko_resp(int delay, char *vm_name, int vm_eth,
                               char *lan, char *label);
void mueth_event_init(void);


