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
char *get_mac_with_name(char *name);
char *get_name_with_mac(char *mac);
void packet_bootp_input(t_machine *machine, 
                        char *src_mac, char *dst_mac,
                        int len, char *data);
void set_dhcp_addr(char *name, int vm_id, int num, char *mac);
void unset_dhcp_addr(char *name, int vm_id, int num, char *mac);
void init_bootp(void);
/*---------------------------------------------------------------------------*/
