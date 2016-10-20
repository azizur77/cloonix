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
char *utils_dir_conf(int vm_id);
char *utils_dir_conf_tmp(int vm_id);
int utils_get_pid_of_machine(t_vm *vm);
char *utils_get_root_fs(char *rootfs);
void utils_chk_my_dirs(t_vm *vm);
void utils_launched_vm_death(char *nm, int error_death);
void utils_finish_vm_init(void *vname);
char *utils_get_kernel_path_name(char *gkernel);
char *utils_get_cow_path_name(int vm_id);
void utils_send_creation_info(char *name, char **argv);
int utils_execve(void *ptr);
void utils_vm_create_fct_abort(void *data);
char *utils_get_uname_r_mod_path(void);
void utils_init(void);
int utils_get_uid_user(void);
int utils_get_gid_user(void);
char *utils_get_intf_prefix(int is_serial, int vm_id);
char *utils_get_cdrom_path_name(int vm_id);

char *utils_path_to_tux(void);
char *utils_get_disks_path_name(int vm_id);
char *utils_get_qmonitor_path(int vm_id);
char *utils_get_qmp_path(int vm_id);
char *utils_get_qhvc0_path(int vm_id);
char *utils_get_qbackdoor_path(int vm_id);
char *utils_get_qbackdoor_hvc0_path(int vm_id);

char *utils_get_tmux_bin_path(void);
char *utils_get_tmux_sock_path(void);
char *utils_get_qemu_img(void);
char *utils_qemu_img_derived(char *backing_file, char *derived_file);
void utils_qemu_img_copy_backing(char *cow, char *dest, char *cmd);
int spice_libs_exists(void);
char *utils_get_spice_path(int vm_id);
/*--------------------------------------------------------------------------*/
char *utils_get_cloonix_switch_path(void);
/*--------------------------------------------------------------------------*/
char *utils_get_tux_path(char *name);
/*--------------------------------------------------------------------------*/
void free_wake_up_eths(t_vm *vm);
/*--------------------------------------------------------------------------*/
char *utils_get_muswitch_bin_path(void);
char *utils_get_musat_bin_path(int musat_type);
/*--------------------------------------------------------------------------*/
char *utils_get_muswitch_sock_dir(void);
char *utils_get_muswitch_key_dir(void);
char *utils_get_muswitch_traf_dir(void);
/*--------------------------------------------------------------------------*/
char *utils_get_mueth_path(int vm_id, int eth_num);
char *utils_get_mueth_name(char *name, int eth_num);
/*--------------------------------------------------------------------------*/
char *utils_mulan_get_sock_path(char *name);
/*--------------------------------------------------------------------------*/
char *utils_get_musat_sock_dir(void);
char *utils_get_musat_path(char *name);
char *utils_get_musat_name(char *name);
/*--------------------------------------------------------------------------*/
void start_mueth_qemu(t_vm *vm);
/*--------------------------------------------------------------------------*/
void utils_format_gene(char *start, char *err, char *name, char **argv);
/****************************************************************************/










