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
void qmp_begin_qemu_unix(char *name);
int qmp_end_qemu_unix(char *name);
int  qmp_still_present(void);
void qmp_vm_delete(char *name);
void qmp_agent_sysinfo(char *name, int used_mem_agent);
void qmp_request_qemu_reboot(char *name);
int qmp_request_qemu_stop_cont(char *name, int cont);
void init_qmp(void);
int get_probably_stopped_cpu(char *name);
/*--------------------------------------------------------------------------*/
