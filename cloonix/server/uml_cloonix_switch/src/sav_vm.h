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
void sav_all_vm_rootfs(int nb, t_vm *vm, char *dir_path,
                       int llid, int tid, int type);
void sav_vm_rootfs(char *name, char *path, int llid, int tid, int stype);
void sav_vm_fifreeze_fithaw(char *name, int is_freeze);
int sav_vm_count(void);
int sav_vm_agent_ok_name(char *name);
int sav_vm_agent_ok_all(void);
void sav_vm_init(void);

