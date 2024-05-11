TARGET="`echo $TARGET`"

gplt_ver=`gnuplot --version |awk '{print $2}'`

set macros

if( gplt_ver >= 5.0){
   #command line argument '$0~$9' has been deprecated in 5.0
  if (ARG1 eq "") {
    # Sized for one column of a two column, 7.5" wide body
    # SIZE="3.05in,1.8in"

    # Sized for one column 6" wide body
    SIZE="3in,2.2in"
  } else {
    if (ARG1 eq "2col") {
      # Sized for 6" wide body
      #SIZE="2.95in,2.2in"
      # 5.5" wide body
      SIZE="2.7in,2.2in"
    } else {
      if (ARG1 eq "3col") {
        SIZE="2.25in,1.6in"
      } else {
        if (ARG1 eq "2x2") {
          # Sized for a 2x2 multiplot on a 6" wide body
          #SIZE="6in,4in"
          # 5.5" wide body
          SIZE="5.5in,3.7in"
        } else {
          SIZE=ARG1
        }
      }
    }
  }
}else{
  if ("$0" eq "" || "$0"[0:1] eq "$$"[0:1]) {
    # Sized for one column of a two column, 7.5" wide body
    # SIZE="3.05in,1.8in"

    # Sized for one column 6" wide body
    SIZE="3in,2.2in"
  } else {
    if ("$0" eq "2col") {
      # Sized for 6" wide body
      #SIZE="2.95in,2.2in"
      # 5.5" wide body
      SIZE="2.7in,2.2in"
    } else {
      if ("$0" eq "3col") {
        SIZE="2.25in,1.6in"
      } else {
        if ("$0" eq "2x2") {
          # Sized for a 2x2 multiplot on a 6" wide body
          #SIZE="6in,4in"
          # 5.5" wide body
          SIZE="5.5in,3.7in"
        } else {
          SIZE="$0"
        }
      }
    }
  }
}
if (!exists("SLIDES_SIZE")) {
  SLIDES_SIZE="720,500"
}

# Note: If you change the default font size, change \gpcode
TIKZ_FONT=exists("TIKZ_FONT") ? TIKZ_FONT : "'\\figureversion{tab},10'"
if (TARGET eq "paper-tikz") {
  set term tikz size @SIZE font @TIKZ_FONT
  set output
  set pointsize 1.5
  set key spacing 1.35
} else {
  if (TARGET eq "pdf") {
    set term pdfcairo size @SIZE linewidth 1 rounded font ',5'
    set output
  } else {
    if (TARGET eq "slides") {
      set term svg size @SLIDES_SIZE font "Open Sans,20" dashed linewidth 2 enhanced
#      set output
      set output "|sed 's/<svg/& style=\"font-weight:300\"/'"
    } else {
      if (!(TARGET eq "")) {
        if (TARGET eq "paper-epslatex") {
          set term epslatex color colortext size @SIZE input font 6 header "\\scriptsize"
          set output
          set pointsize 1.5
          set key spacing 1.35
        } else {
          print sprintf("Unknown target %s!", TARGET)
        }
      }
    }
  }
}

set ytics nomirror
set xtics nomirror
set grid back lt 0 lt rgb '#999999'
set border 3 back

set linetype 1 lw 1 lc rgb '#00dd00'
set linetype 2 lw 1 lc rgb '#0000ff'
set linetype 3 lw 1 lc rgb '#ff0000'

set style line 1 lt rgb "#A00000" lw 1 pt 1 ps 0.5
set style line 2 lt rgb "#5060D0" lw 1 pt 2 ps 0.5

set style line 3 lt rgb "#F25900" lw 1 pt 3 ps 0.5
set style line 4 lt rgb "#008AB8" lw 1 pt 4 ps 0.5

set style line 5 lt rgb "#F25900" lw 1 pt 5
set style line 6 lt rgb "#F25900" lw 1 pt 6

set style line 7 lt rgb "#008AB8" lw 1 pt 7
set style line 8 lt rgb "#008AB8" lw 1 pt 8

# set style line 9 lt rgb "#008AB8" lw 1 pt 2
set style line 9 lt rgb "#A40044" lw 3 pt 2
set style line 10 lt rgb "#002E00" lw 1 pt 3

#set style line 1 lt rgb "#A00000" lw 1 pt 1
#set style line 2 lt rgb "#00A000" lw 1 pt 2
#set style line 3 lt rgb "#5060D0" lw 1 pt 3
#set style line 4 lt rgb "#F25900" lw 1 pt 4
#set style line 5 lt rgb "#008AB8" lw 1 pt 6
#set style line 6 lt rgb "#002E00" lw 1 pt 8
C1 = "#A00000"
C2 = "#00A000"
C3 = "#5060D0"
C4 = "#F25900"
C5 = "#008ABB"
C6 = "#002E00"
C7 = "#e28743"
C8 = "#eab676"

set style line 50 lc rgb 'black' lt 1 lw 1.5

hist_pattern_0=7
hist_pattern_1=1
hist_pattern_2=2
hist_pattern_3=7

cs = 1
c = 2
s = 3

stock = 1
cna = 2
cst = 3
mcstp = 3
cohort = 4
sys = 5
mcs = 6
hmcs = 7
malthusian = 8
bravo = 6
sysbravo = 7


cstock = C1
ccna = C2
ccst = C3
ccohort = C4
csys = C5

set ytics nomirror
set xtics nomirror
set grid back lt 0 lt rgb '#999999'
set border 3 back

if( gplt_ver >= 5.0){
  set style line 1 dt 1 lc rgb C1 lw 2
  set style line 2 dt (2,2) lc rgb C2 lw 2
  set style line 3 dt (1,1) lc rgb C3 lw 2
  set style line 4 dt 3 lc rgb C4 lw 2
  set style line 5 dt 4 lc rgb C5 lw 2
  set style line 6 dt 5 lc rgb C6 lw 2
}else{
  set style line 1 lt 1 lc rgb C1 lw 2
  set style line 2 lt (2,2) lc rgb C2 lw 2
  set style line 3 lt (1,1) lc rgb C3 lw 2
  set style line 4 lt 3 lc rgb C4 lw 2
  set style line 5 lt 4 lc rgb C5 lw 2
  set style line 6 lt 5 lc rgb C6 lw 2
}

#
# Multiplot stuff
#

mp_startx=0.090                 # Left edge of col 0 plot area
mp_starty=0.120                 # Top of row 0 plot area
mp_width=0.825                  # Total width of plot area
mp_height=0.780                 # Total height of plot area
mp_colgap=0.07                  # Gap between columns
mp_rowgap=0.15                  # Gap between rows
# The screen coordinate of the left edge of column col
mp_left(col)=mp_startx + col*((mp_width+mp_colgap)/real(mp_ncols))
# The screen coordinate of the top edge of row row
mp_top(row)=1 - (mp_starty + row*((mp_height+mp_rowgap)/real(mp_nrows)))

# Set up a multiplot with w columns and h rows
mpSetup(w,h) = sprintf('\
    mp_nplot=-1; \
    mp_ncols=%d; \
    mp_nrows=%d; \
    set multiplot', w, h)
# Start the next graph in the multiplot
mpNext = '\
    mp_nplot=mp_nplot+1; \
    set lmargin at screen mp_left(mp_nplot%mp_ncols); \
    set rmargin at screen mp_left(mp_nplot%mp_ncols+1)-mp_colgap; \
    set tmargin at screen mp_top(mp_nplot/mp_ncols); \
    set bmargin at screen mp_top(mp_nplot/mp_ncols+1)+mp_rowgap; \
    unset label 1'

# Set Y axis row label such that it aligns regardless of tic width
mpRowLabel(lbl) = \
    sprintf('set label 1 "%s" at graph -0.25,0.5 center rotate',lbl)

#
# Slides stuff
#

if (TARGET eq "slides") {
  set style line 1 lt 1 lc rgb "#8ae234" lw 4
  set style line 2 lt 1 lc rgb "#000000" lw 4

  # Based on
  # http://youinfinitesnake.blogspot.com/2011/02/attractive-scientific-plots-with.html

  # Line style for axes
  #set style line 80 lt 1
  #set style line 80 lt rgb "#808080"

  # Line style for grid
  #set style line 81 lt 3  # Dotted
  #set style line 81 lt rgb "#808080" lw 0.5

  #set grid back linestyle 81
  #set border 3 back linestyle 80
}
