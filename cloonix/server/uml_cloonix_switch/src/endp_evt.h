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
int  endp_exists(char *name, int num);
int  endp_lan_full(char *name, int num, int *tidx);
int  endp_lan_find(char *name, int num, char *lan, int *tidx);
int  endp_lan_is_in_use(char *lan);
void endp_add_lan(int llid, int tid, char *name, int num,
                  char *lan, int tidx);
int  endp_del_lan(char *name, int num, int tidx, char *lan);
void endp_mulan_birth(char *lan);
void endp_mulan_death(char *lan);
void endp_connect_OK(char *name, int num, char *lan, int tidx, int rank);
void endp_connect_KO(char *name, int num, char *lan, int tidx);
void endp_birth(char *name, int num, int endp_type);
int  endp_death(char *name, int num);
void endp_quick_death(char *name, int num);
void endp_init(void);
