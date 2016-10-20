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
int musat_event_exists(char *name);

int musat_event_already_in_lan(char *name, int num);
int musat_event_lan_is_in_use(char *lan, int num);

void musat_event_admin_add_lan(int llid, int tid, 
                               char *name, int num, char *lan);
int musat_event_admin_del_lan(char *name, int num, char *lan);

void musat_event_mulan_birth(char *lan);
void musat_event_mulan_death(char *lan);
void musat_event_connect_OK(char *name, char *lan, int num, int rank);
void musat_event_connect_KO(char *name, char *lan, int num);
char *musat_get_attached_lan(char *name, int num);
void musat_event_birth(char *name, int musat_type);
int musat_event_death(char *name);
void musat_event_quick_death(char *name);
void musat_event_timer_ko_resp(int delay, char *name, int num, 
                               char *lan, char *reason);
void musat_event_init(void);


