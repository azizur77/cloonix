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
#include <cairo.h>
#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <math.h>
#include <time.h>
#include <string.h>

#include "io_clownix.h"
#include "bdplot.h"
#include "gtkplot.h"


static float g_maxrange = 5000;

static const int default_precision_graph = 1024;
static int precision_graph = 1024; //in ms, relative to default scaleX

static float rayon = 2;

static const float defaultscaleX = 64;
static float scaleX = 64; //=1 for 1px on graph per second; =1000 for 1px on graph per millisecond etc

static float scaleXMIN = 1;
static float scaleXMAX = 512;

static float marginX = 80;
static float marginY = 30;


static float ColorBallsR[] = { 0, 0.8,0,0,0,0,0,0,0,0};
static float ColorBallsG[] = { 0, 0,0.8,0,0,0,0,0,0,0};
static float ColorBallsB[] = { 0.8, 0,0,0,0,0,0,0,0,0};

static float ColorLinkR[] = { 0, 0.5,0,0,0,0,0,0,0,0};
static float ColorLinkG[] = { 0, 0,0.5,0,0,0,0,0,0,0};
static float ColorLinkB[] = { 0.5, 0,0,0,0,0,0,0,0,0};


///////STRUCS///////////

typedef struct Dot Dot;

struct Dot
{
  float x;
  float y;
  Dot *prevdot;
  float r;
  float g;
  float b;
};

typedef struct t_destroy_data
{
  char name[MAX_NAME_LEN];
  int num;
} t_destroy_data;

/////////FUNCTIONS DECLARATIONS////////////
static gboolean onscroll(GtkWidget *widget, GdkEventScroll *event, gpointer user_data);

static void do_drawing(cairo_t *cr);
static void addot(float x,float y,int ind);

/////////VARIABLES DECLARATIONS////////////
static GtkWidget *g_plot_window;

static GArray *dots[NCURVES];


//////////EVENTS//////////////////

static gboolean on_draw_event(GtkWidget *widget, cairo_t *cr, gpointer user_data)
{
  do_drawing(cr);
  return FALSE;
}

static gboolean onscroll(GtkWidget *widget, GdkEventScroll *event, gpointer user_data)
{
  if(event->direction==1)
  {
    scaleX*=0.5;
    if(scaleX<=scaleXMIN)scaleX=scaleXMIN;
    precision_graph=default_precision_graph*(defaultscaleX/scaleX);
  }
  else if(event->direction==0)
  {
    scaleX*=2;
    if(scaleX>=scaleXMAX)scaleX=scaleXMAX;
    precision_graph=default_precision_graph*(defaultscaleX/scaleX);
  } 
  return FALSE;
}

//////////////UTILITY FUNCTIONS//////////////

Dot *bal;
static void addot(float x,float y,int ind)
{
  bal = malloc(sizeof(Dot));
  memset(bal,0,sizeof(Dot));

  bal->x = x;
  bal->y = y;
  bal->r = ColorBallsR[ind];
  bal->g = ColorBallsG[ind];
  bal->b = ColorBallsB[ind];
  if(dots[ind]->len > 0)
  {
    bal->prevdot = g_array_index(dots[ind], Dot *, (dots[ind]->len)-1);
  }
  else bal->prevdot=NULL;

  //printf("%p\n",bal);
  g_array_append_val (dots[ind], bal);

  Dot *first = g_array_index(dots[ind], Dot *, 0);
  while(first->x < bal->x*scaleXMIN - g_maxrange)
  {
    g_array_remove_index(dots[ind],0);
    first = g_array_index(dots[ind], Dot *, 0);
  }
}




/****************************************************************************/
static void do_drawing(cairo_t *cr)
{
  int w = gtk_widget_get_allocated_width (g_plot_window);
  int h = gtk_widget_get_allocated_height (g_plot_window);

  if(w<50)w=50;
  if(h<50)h=50;

  float decalagex = 0; //How much to offset the drawing
  float decalagey = 0;
  float maxheight = 0;

  float basedecalx = marginX;
  float basedecaly = h-marginY;

  for(int ind=0;ind<NCURVES;ind++)
  {
    float tempdx = 0;
    if(dots[ind]->len>0)tempdx = w-((g_array_index(dots[ind], Dot *, (dots[ind]->len)-1)->x)*scaleX+marginX+20);

    if(tempdx<decalagex)decalagex=tempdx;

    for(int i = 0;i<dots[ind]->len;i++)
    {
      Dot *bali = g_array_index(dots[ind], Dot *, i);
      if(-bali->y>maxheight)maxheight=-bali->y;
    }
  }

  float scaleY = (h-marginY-h/5)/maxheight;

  decalagey+= basedecaly; //To center on the y axis, with the bottom margin
  decalagex+=basedecalx; //for the left margin

  //ARROWS
  cairo_set_source_rgb(cr,0,0,0);

  cairo_move_to(cr, marginX, h-marginY);
  cairo_line_to(cr, w-30, h-marginY);
  cairo_stroke(cr);

  cairo_move_to(cr, w-30, h-marginY);
  cairo_line_to(cr, w-30-7, h-marginY-7);
  cairo_stroke(cr);

  cairo_move_to(cr, w-30, h-marginY);
  cairo_line_to(cr, w-30-7, h-marginY+7);
  cairo_stroke(cr);

  ///

  cairo_move_to(cr, marginX, h-marginY);
  cairo_line_to(cr, marginX, marginY);
  cairo_stroke(cr);

  cairo_move_to(cr, marginX, marginY);
  cairo_line_to(cr, marginX-7, marginY+7);
  cairo_stroke(cr);

  cairo_move_to(cr, marginX, marginY);
  cairo_line_to(cr, marginX+7, marginY+7);
  cairo_stroke(cr);

  ///

  cairo_set_font_size(cr, 20);

  //cairo_move_to(cr, marginX*0.2, h-marginY*0.2);
  //cairo_show_text(cr, "0"); 

  cairo_move_to(cr, marginX*0.2, 20);
  cairo_show_text(cr, "kBps");

  cairo_set_source_rgb(cr,ColorLinkR[0],ColorLinkG[0],ColorLinkB[0]);
  cairo_move_to(cr, marginX*0.2+100, 20);
  cairo_show_text(cr, "RX");

  cairo_set_source_rgb(cr,ColorLinkR[1],ColorLinkG[1],ColorLinkB[1]);
  cairo_move_to(cr, marginX*0.2+180, 20);
  cairo_show_text(cr, "TX");

  cairo_set_source_rgb(cr,0,0,0);

  cairo_move_to(cr, w-100, h-marginY*0.2);
  cairo_show_text(cr, "time(s)");

  //LABEL TIME AXE
  float mintime = (basedecalx-decalagex)/scaleX*1000/precision_graph;
  float maxtime = mintime+(w-marginX-80)/scaleX*1000/precision_graph;

  int mint = (int)mintime+1;
  int maxt = (int)maxtime;

  cairo_set_font_size(cr, 12);
  for(int i = mint;i<maxt;i++)
  {

    char output[5];

    snprintf(output, 5, "%f", (float)i*precision_graph/1000);

    cairo_move_to(cr, decalagex+i*scaleX/1000*precision_graph, h-marginY+3);
    cairo_line_to(cr, decalagex+i*scaleX/1000*precision_graph, h-marginY-3);
    cairo_stroke(cr);

    cairo_move_to(cr, decalagex+i*scaleX/1000*precision_graph-10, h-marginY*0.3);
    cairo_show_text(cr, output);
  }

  //LABEL KBPS AXE
  float minkb = 0;

  float maxkb = (h-marginY-50)/scaleY*1000;
  int precisionkb = (int)(maxkb/10);
  maxkb/=precisionkb;

  int mink = (int)minkb+1;
  int maxk = (int)maxkb;

  cairo_set_font_size(cr, 12);
  for(int i = mink;i<maxk;i++)
  {

    char output[7];

    snprintf(output, 7, "%d", (int)i*precisionkb/1000);

    cairo_move_to(cr, marginX-3, h-marginY-i*scaleY/1000*precisionkb);
    cairo_line_to(cr, marginX+3, h-marginY-i*scaleY/1000*precisionkb);
    cairo_stroke(cr);

    cairo_move_to(cr, 20,  h-marginY-i*scaleY/1000*precisionkb+5);
    cairo_show_text(cr, output);
  }
  ///END ARROWS

  for(int ind=0;ind<NCURVES;ind++)
  {
    for(int i = 0;i<dots[ind]->len;i++)
    {

      Dot *bali = g_array_index(dots[ind], Dot *, i);

      if (decalagex+bali->x*scaleX>basedecalx)
      {
        //lines
        if(bali->prevdot && decalagex+bali->prevdot->x*scaleX>basedecalx)
        {
          cairo_set_source_rgb(cr,ColorLinkR[ind],ColorLinkG[ind],ColorLinkB[ind]);

          cairo_move_to(cr, decalagex+(scaleX*bali->x), scaleY*bali->y+decalagey);
          cairo_line_to(cr, decalagex+(scaleX*bali->prevdot->x), scaleY*bali->prevdot->y+decalagey);
          cairo_stroke(cr);

          cairo_move_to(cr, 0, 0);
        }

        //dots
        cairo_set_source_rgb(cr,bali->r,bali->g,bali->b);
        cairo_arc(cr, decalagex+(scaleX*bali->x), scaleY*bali->y+decalagey, rayon, 0, 2 * M_PI);
        cairo_fill(cr);
      }
    }
  }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void destroy(GtkWidget *widget, gpointer data)
{
  t_destroy_data *dd = (t_destroy_data *) data;
  bdplot_destroy(dd->name, dd->num);
  free(data);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void gtkplot_newdata(float date_s, float *bd)
{
  static float g_last_date_s = 0;
  int i;
  float delta_s = date_s - g_last_date_s;
  if (g_last_date_s != 0)
    {
    if (delta_s < 0.001)
      KERR("%f %f", date_s, g_last_date_s);
    else
      {
      for(i=0;i<NCURVES;i++)
        addot(date_s, -(bd[i]/delta_s), i);
      gtk_widget_queue_draw(g_plot_window);
      }
    }
  g_last_date_s = date_s;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void gtkplot_create(char *name, int num)
{
   char title[MAX_NAME_LEN];
   GtkWidget *darea;
   int ind;
   t_destroy_data *dd = (t_destroy_data *) malloc(sizeof(t_destroy_data));
   memset(dd, 0, sizeof(t_destroy_data));
   memset(title, 0, MAX_NAME_LEN);
   snprintf(title, MAX_NAME_LEN-1, "%s_eth%d", name, num);
   strncpy(dd->name, name, MAX_NAME_LEN-1);
   dd->num = num;
   for(ind = 0;ind<NCURVES;ind++)
   {
     dots[ind] = g_array_new (false, false, sizeof (Dot *));
   }
  g_plot_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
   darea = gtk_drawing_area_new();
   g_signal_connect(G_OBJECT(g_plot_window), "destroy", G_CALLBACK(destroy), NULL);
   gtk_container_add(GTK_CONTAINER(g_plot_window), darea);
   gtk_widget_set_events (g_plot_window, GDK_EXPOSURE_MASK
           | GDK_LEAVE_NOTIFY_MASK   | GDK_POINTER_MOTION_MASK
           | GDK_BUTTON_PRESS_MASK | GDK_SCROLL_MASK
           | GDK_BUTTON_RELEASE_MASK);
   g_signal_connect(G_OBJECT(darea), "draw", G_CALLBACK(on_draw_event), NULL);
   g_signal_connect(g_plot_window, "scroll-event", G_CALLBACK(onscroll), NULL);
   gtk_window_set_position(GTK_WINDOW(g_plot_window), GTK_WIN_POS_CENTER);
   gtk_window_set_default_size(GTK_WINDOW(g_plot_window), 400, 300);
   gtk_window_set_title(GTK_WINDOW(g_plot_window), title);
  gtk_widget_show_all(g_plot_window);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void gtkplot_init(void)
{
  g_maxrange = 5000;
}
/*--------------------------------------------------------------------------*/


