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
#include <gtk/gtk.h>
#include <libcrcanvas.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <net/if.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>


#include "io_clownix.h"
#include "rpc_clownix.h"
#include "commun_consts.h"
#include "bank.h"
#include "interface.h"
#include "doorways_sock.h"
#include "client_clownix.h"
#include "menu_utils.h"
#include "menus.h"
#include "move.h"
#include "popup.h"
#include "main_timer_loop.h"
#include "pid_clone.h"
#include "cloonix.h"
#include "eventfull_eth.h"
#include "layout_rpc.h"
#include "layout_topo.h"
#include "menu_dialog_kvm.h"
#include "file_read_write.h"
#include "menu_dialog_c2c.h"
#include "menu_dialog_lan.h"
#include "cloonix_conf_info.h"
#include "bdplot.h"


extern char **environ;


/*--------------------------------------------------------------------------*/
gboolean refresh_request_timeout (gpointer  data);
void topo_set_signals(GtkWidget *window);
GtkWidget *topo_canvas(void);


static t_topo_clc g_clc;

static int eth_choice = 0;
static GtkWidget *g_main_window;

static int g_i_am_in_cloonix;
static char g_i_am_in_cloonix_name[MAX_NAME_LEN];

static gint main_win_x, main_win_y, main_win_width, main_win_height;
static guint main_timeout;
static char g_current_directory[MAX_PATH_LEN];
static char g_doors_client_addr[MAX_PATH_LEN];
static char g_cloonix_root_tree[MAX_PATH_LEN];
static char g_dtach_work_path[MAX_PATH_LEN];
static char g_password[MSG_DIGEST_LEN];
static char **g_saved_environ;
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
int wireshark_qt_present_in_server(void)
{
  int result = 0;
  if (g_clc.flags_config & FLAGS_CONFIG_WIRESHARK_QT_PRESENT) 
    result = 1;
  return result;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
int wireshark_present_in_server(void)
{
  int result = 0;
  if ((g_clc.flags_config & FLAGS_CONFIG_WIRESHARK_QT_PRESENT) ||
      (g_clc.flags_config & FLAGS_CONFIG_WIRESHARK_PRESENT))
    result = 1;
  return result;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
char *get_wireshark_present_in_server(void)
{
  if (g_clc.flags_config & FLAGS_CONFIG_WIRESHARK_QT_PRESENT)
    return (WIRESHARK_BINARY_QT);
  else if (g_clc.flags_config & FLAGS_CONFIG_WIRESHARK_PRESENT)
    return (WIRESHARK_BINARY);
  else
    KERR("NO WIRESHARK ON SERVER");
  return "NO_WIRESHARK";
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
char *get_password(void)
{
  return g_password;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static int file_exists_exec(char *path)
{
  int err, result = 0;
  err = access(path, X_OK);
  if (!err)
    result = 1;
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
char *local_get_cloonix_name(void)
{
  return (g_clc.network);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int get_vm_config_flags(t_custom_vm *cust_vm)
{
  int vm_config_flags = 0;
  if (cust_vm->is_full_virt)
    vm_config_flags |= VM_CONFIG_FLAG_FULL_VIRT;
  if (cust_vm->is_ballooning)
    vm_config_flags |= VM_CONFIG_FLAG_BALLOONING;
  if (cust_vm->is_persistent)
    {
    vm_config_flags |= VM_CONFIG_FLAG_PERSISTENT;
    vm_config_flags &= ~VM_CONFIG_FLAG_EVANESCENT;
    }
  else
    {
    vm_config_flags &= ~VM_CONFIG_FLAG_PERSISTENT;
    vm_config_flags |= VM_CONFIG_FLAG_EVANESCENT;
    }
  if (cust_vm->has_p9_host_share)
    vm_config_flags |= VM_CONFIG_FLAG_9P_SHARED;
  return vm_config_flags;
}
/*--------------------------------------------------------------------------*/


/*****************************************************************************/
int inside_cloonix(char **name)
{
  *name = g_i_am_in_cloonix_name;
  return g_i_am_in_cloonix;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
char *get_doors_client_addr(void)
{
  return g_doors_client_addr;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void cloonix_get_xvt(char *xvt)
{
  memset(xvt, 0, MAX_PATH_LEN);
  if (!file_exists_exec("/usr/bin/urxvt"))
    {
    if (!file_exists_exec("/bin/xterm"))
      KOUT("\n\nInstall \"rxvt-unicode\" or \"xterm\"\n\n");
    else
      strncpy(xvt, "/bin/xterm", MAX_PATH_LEN-1);
    }
  else
    strncpy(xvt, "/usr/bin/urxvt", MAX_PATH_LEN-1);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static const char *get_dtach_work_path(void)
{
  return (g_dtach_work_path);
}
/*--------------------------------------------------------------------------*/



/*****************************************************************************/
char *get_local_cloonix_tree(void)
{
  return g_cloonix_root_tree;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
char *get_distant_cloonix_tree(void)
{
  return g_clc.bin_dir;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
char **get_argv_local_dbssh(char *name)
{
  static char bin_path[MAX_PATH_LEN];
  static char doors_addr[MAX_PATH_LEN];
  static char username[2*MAX_NAME_LEN];
  static char cmd[2*MAX_PATH_LEN];
  static char nm[MAX_NAME_LEN];
  static char title[2*MAX_NAME_LEN];
  static char xvt[MAX_PATH_LEN];
  static char *argv[] = {xvt, "-T", title, "-e",  
                         bin_path, doors_addr, g_password, 
                         "-t", username, cmd, NULL};
  memset(cmd, 0, 2*MAX_PATH_LEN);
  memset(bin_path, 0, MAX_PATH_LEN);
  memset(doors_addr, 0, MAX_PATH_LEN);
  memset(username, 0, 2*MAX_NAME_LEN);
  memset(nm, 0, MAX_NAME_LEN);
  memset(title, 0, 2*MAX_NAME_LEN);
  cloonix_get_xvt(xvt);


  strncpy(nm, name, MAX_NAME_LEN-1);
  snprintf(title, 2*MAX_NAME_LEN-1, "%s/%s", local_get_cloonix_name(), nm); 
  snprintf(bin_path,  MAX_PATH_LEN-1, 
           "%s/common/agent_dropbear/agent_bin/dropbear_cloonix_ssh", 
           get_local_cloonix_tree());
  strncpy(doors_addr, get_doors_client_addr(), MAX_PATH_LEN-1);
  snprintf(username, MAX_PATH_LEN-1, "local_host_dropbear");
  snprintf(cmd, 2*MAX_PATH_LEN-1, 
           "%s/server/dtach/dtach -a %s/%s; sleep 10", 
           get_distant_cloonix_tree(), get_dtach_work_path(), nm);
//  KERR("%s %s %s -t %s %s\n", bin_path, doors_addr, g_password, username, cmd);
  return (argv);
}
/*--------------------------------------------------------------------------*/


/*****************************************************************************/
GtkWidget *get_main_window(void)
{
  return g_main_window;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
char *get_spice_vm_path(int vm_id)
{
  static char path[MAX_PATH_LEN];
  memset(path, 0, MAX_PATH_LEN);
  snprintf(path,MAX_PATH_LEN-1, "%s/vm/vm%d/%s", 
           g_clc.work_dir, vm_id, SPICE_SOCK);
  return(path);
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
char *get_path_to_qemu_spice(void)
{
  char *result = NULL;
  static char path[MAX_PATH_LEN];
  sprintf(path,"%s/common/spice/spice_lib/bin/spicy",get_local_cloonix_tree());
  if (file_exists_exec(path))
    result = path;
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
char *get_path_to_nemo_icon(void)
{
  char *result = NULL;
  static char path[MAX_PATH_LEN];
  sprintf(path, 
          "%s/client/lib_client/include/clownix64.png", 
          get_local_cloonix_tree());
  if (is_file_readable(path))
    result = path;
  return result;
}
/*---------------------------------------------------------------------------*/



/*****************************************************************************/
char *get_current_directory(void)
{
  return g_current_directory;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void set_main_window_coords(int x, int y, int width, int heigh)
{
  main_win_x = x;
  main_win_y = y;
  main_win_width = width;
  main_win_height = heigh;
  set_popup_window_coords();
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void init_set_main_window_coords(void)
{
  gtk_window_get_position(GTK_WINDOW(g_main_window), &main_win_x, &main_win_y);
  gtk_window_get_size(GTK_WINDOW(g_main_window), 
                      &main_win_width, &main_win_height);
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
void get_main_window_coords(gint *x, gint *y, gint *width, gint *heigh)
{
  *x = main_win_x;
  *y = main_win_y;
  *width = main_win_width;
  *heigh = main_win_height;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void put_top_left_icon(GtkWidget *mainwin)
{
  GtkWidget *image;
  GdkPixbuf *pixbuf;
  char *path = get_path_to_nemo_icon();
  image = gtk_image_new_from_file (path);
  pixbuf = gtk_image_get_pixbuf(GTK_IMAGE(image));
  gtk_window_set_icon(GTK_WINDOW(mainwin), pixbuf);
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
void destroy_handler (GtkWidget *win, gpointer data)
{
  pid_clone_kill_all();
  sleep(2);
  if (data)
    KOUT(" ");
  if (win != g_main_window)
    KOUT(" ");
  if (g_source_remove(main_timeout))
    g_print ("OK\n"); 
  else
    g_print ("KO\n"); 
}
/*--------------------------------------------------------------------------*/


/****************************************************************************/
void my_mkdir(char *dst_dir)
{
  struct stat stat_file;
  char copy1_dir[MAX_PATH_LEN];
  char copy2_dir[MAX_PATH_LEN];
  char *up_one, *up_two;
  memset(copy1_dir, 0, MAX_PATH_LEN);
  strncpy(copy1_dir, dst_dir, MAX_PATH_LEN-1);
  memset(copy2_dir, 0, MAX_PATH_LEN);
  strncpy(copy2_dir, dst_dir, MAX_PATH_LEN-1);
  up_one = dirname(copy2_dir); 
  up_two = dirname(up_one); 
  up_one = dirname(copy1_dir); 
  if (strlen(up_two) > 2) 
    {
    if (stat(up_two, &stat_file))
      if (mkdir(up_two, 0777))
        KOUT("%s, %d", up_two, errno);
    }
  if (strlen(up_one) > 2) 
    {
    if (stat(up_one, &stat_file))
      if (mkdir(up_one, 0777))
        KOUT("%s, %d", up_two, errno);
    }
  if (mkdir(dst_dir, 0777))
    {
    if (errno != EEXIST)
      KOUT("%s, %d", dst_dir, errno);
    else
      {
      if (stat(dst_dir, &stat_file))
        KOUT("%s, %d", dst_dir, errno);
      if (!S_ISDIR(stat_file.st_mode))
        {
        unlink(dst_dir);
        if (mkdir(dst_dir, 0777))
          KOUT("%s, %d", dst_dir, errno);
        }
      }
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void main_timer_activation(void)
{
  if (main_timeout)
    g_source_remove(main_timeout);
  main_timeout = g_timeout_add(100,refresh_request_timeout,(gpointer) NULL);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void work_dir_resp(int tid, t_topo_clc *conf)
{
  char title[MAX_NAME_LEN];
  GtkWidget *window, *vbox;
  GtkWidget *scrolled;
  eth_choice = 0;
  if (strcmp(conf->version, cloonix_conf_info_get_version()))
    {
    printf("\n\nCloonix Version client:%s DIFFER FROM server:%s\n\n", 
           cloonix_conf_info_get_version(), conf->version);
    exit(-1);
    }
  daemon(0,0);
  move_init();
  menu_init();
  popup_init();
  memcpy(&g_clc, conf, sizeof(t_topo_clc));
  snprintf(g_dtach_work_path, MAX_PATH_LEN-1, "%s/%s",
                             g_clc.work_dir, DTACH_SOCK);
  if (gtk_init_check(NULL, NULL) == FALSE)
    KOUT("Error in gtk_init_check function");

  window = gtk_window_new (GTK_WINDOW_TOPLEVEL);

  g_main_window = window;
  init_set_main_window_coords();
  g_signal_connect (G_OBJECT (window), "destroy",
		      (GCallback) destroy_handler, NULL);
  if (g_i_am_in_cloonix)
    snprintf(title, MAX_NAME_LEN, "%s/%s", 
             g_i_am_in_cloonix_name, local_get_cloonix_name());
  else
    snprintf(title, MAX_NAME_LEN, "%s", local_get_cloonix_name());
  gtk_window_set_title (GTK_WINDOW (window), title);
  gtk_window_set_default_size (GTK_WINDOW (window), WIDTH, HEIGH);
  put_top_left_icon(window);
  topo_set_signals(window);
  scrolled = gtk_scrolled_window_new(NULL, NULL);
  vbox   = topo_canvas();
  gtk_container_add (GTK_CONTAINER(scrolled), vbox);
  gtk_container_add (GTK_CONTAINER (window), scrolled);
  gtk_widget_show_all(window);
  main_timer_activation();
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void init_local_cloonix_bin_path(char *curdir, char *callbin)
{
  char path[MAX_PATH_LEN];
  char *ptr;
  memset(g_cloonix_root_tree, 0, MAX_PATH_LEN);
  memset(path, 0, MAX_PATH_LEN);
  if (callbin[0] == '/')
    snprintf(path, MAX_PATH_LEN-1, "%s", callbin);
  else
    snprintf(path, MAX_PATH_LEN-1, "%s/%s", curdir, callbin);

  ptr = strrchr(path, '/');
  if (!ptr)
    KOUT("%s", path);
  *ptr = 0;
  ptr = strrchr(path, '/');
  if (!ptr)
    KOUT("%s", path);
  *ptr = 0;
  ptr = strrchr(path, '/');
  if (!ptr)
    KOUT("%s", path);
  *ptr = 0;
  strncpy(g_cloonix_root_tree, path, MAX_PATH_LEN-1);
  snprintf(path, MAX_PATH_LEN-1,
           "%s/client/cairo_canvas/cloonix_gui", g_cloonix_root_tree);
  if (access(path, X_OK))
    KOUT("%s", path);

}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
char **get_saved_environ(void)
{
  return (g_saved_environ);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static char **save_environ(void)
{
  return environ;
/*
  char *tree;
  char *xauthority;
  char ld_lib[MAX_PATH_LEN];
  static char lib_path[MAX_PATH_LEN];
  static char xauth[MAX_PATH_LEN];
  static char username[MAX_NAME_LEN];
  static char home[MAX_PATH_LEN];
  static char logname[MAX_NAME_LEN];
  static char display[MAX_NAME_LEN];
  char **environ;
  static char *environ_simple[]={lib_path, xauth, username,
                                 logname, home, display, NULL};
  tree = get_local_cloonix_tree();
  memset(lib_path, 0, MAX_PATH_LEN);
  memset(xauth, 0, MAX_PATH_LEN);
  if(!getenv("HOME"))
    KOUT(" ");
  if(!getenv("USER"))
    KOUT(" ");
  if(!getenv("DISPLAY"))
    KOUT(" ");
  snprintf(ld_lib, MAX_PATH_LEN-1,
           "%s/common/spice/spice_lib", tree);
  snprintf(lib_path, MAX_PATH_LEN-1, "LD_LIBRARY_PATH=%s", ld_lib);
  setenv("LD_LIBRARY_PATH", ld_lib, 1);
  environ = environ_simple; 
  xauthority = getenv("XAUTHORITY");
  if ((xauthority) && (!access(xauthority, W_OK)))
    snprintf(xauth, MAX_PATH_LEN-1, "XAUTHORITY=%s", xauthority);
  else
    snprintf(xauth,MAX_PATH_LEN-1,"XAUTHORITY=%s/.Xauthority",getenv("HOME"));
  memset(home, 0, MAX_PATH_LEN);
  snprintf(home, MAX_PATH_LEN-1, "HOME=%s", getenv("HOME"));
  memset(display, 0, MAX_NAME_LEN);
  snprintf(display, MAX_NAME_LEN-1, "DISPLAY=%s", getenv("DISPLAY"));
  memset(username, 0, MAX_NAME_LEN);
  snprintf(username, MAX_NAME_LEN-1, "USER=%s", getenv("USER"));
  return environ;
*/
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
int main(int argc, char *argv[])
{
  char xvt[MAX_PATH_LEN];
  t_cloonix_conf_info *cnf;
  g_i_am_in_cloonix = i_am_inside_cloonix(g_i_am_in_cloonix_name);
  main_timeout = 0;
  eth_choice = 0;
  if (argc < 2)
    KOUT("%d", argc);
  if (cloonix_conf_info_init(argv[1]))
    KOUT("%s", argv[1]);
  if (argc < 3)
    {
    printf("\nMISSING NAME:");
    printf("\n\n%s\n\n", cloonix_conf_info_get_names());
    exit(1);
    }
  cnf = cloonix_conf_info_get(argv[2]);
  if (!cnf)
    {
    printf("\nBAD NAME %s:", argv[2]);
    printf("\n\n%s\n\n", cloonix_conf_info_get_names());
    exit(1);
    }
  printf("\nVersion:%s\n", cloonix_conf_info_get_version());
  memset(g_current_directory, 0, MAX_PATH_LEN);
  if (!getcwd(g_current_directory, MAX_PATH_LEN-1))
    KOUT(" ");
  init_local_cloonix_bin_path(g_current_directory, argv[0]); 
  cloonix_get_xvt(xvt);
  printf("\nWill use:\n%s\n", xvt);
  if(!getenv("HOME"))
    KOUT("No HOME env");
  if(!getenv("USER"))
    KOUT("No USER env");
  if(!getenv("DISPLAY"))
    KOUT("No DISPLAY env");

  g_saved_environ = save_environ();
  memset(g_doors_client_addr, 0, MAX_PATH_LEN);
  strncpy(g_doors_client_addr, cnf->doors, MAX_PATH_LEN-1);
  printf("CONNECT TO UNIX SERVER: %s\n", g_doors_client_addr);
  memset(g_password, 0, MSG_DIGEST_LEN);
  strncpy(g_password, cnf->passwd, MSG_DIGEST_LEN-1);
  interface_switch_init(g_doors_client_addr, g_password);
  eventfull_init();
  client_get_path(0, work_dir_resp);
  printf("CONNECTED\n");
  printf("GRAPH PID: %d\n", getpid());
  layout_topo_init();
  request_move_stop_go(1);
  bdplot_init();
  gtk_main();
  return 0;
}
/*--------------------------------------------------------------------------*/


