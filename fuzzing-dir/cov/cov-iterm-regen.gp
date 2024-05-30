call "fuzzing-dir/cov/common.gnuplot" "7.5in, 2.0in"
# set terminal png
set output "`echo $OUT`"
set datafile separator ","

# set multiplot layout 1,6

mp_startx=0.05
mp_starty=0.05
mp_width=0.85
mp_height=0.6
mp_rowgap=0.1
mp_colgap=0.04

eval mpSetup(6, 2)

file_exists(file) = int(system("[ -f '".file."' ] && echo '1' || echo '0'"))

# GlusterFS
eval mpNext
set ylabel 'Branch cov' offset 0,-2.9
unset xlabel
set title '(a) GlusterFS'
set format y "%.1f"
set xtics rotate by 45 offset -0.5,-1
# set ytics 1.5
# set xtics 12
set key at 72,2.5


if ( file_exists("fuzzing-dir/eval/glusterfs/workdir-3-4-non-fault-c/coverages-sfalse-ctrue") && file_exists("fuzzing-dir/eval/glusterfs/workdir-3-4-non-fault-s/coverages-strue-cfalse") && file_exists("fuzzing-dir/eval/glusterfs/workdir-3-4-non-fault-cs/coverages-strue-ctrue")) \
plot '<(cnt=$(head -n 25920 fuzzing-dir/eval/glusterfs/workdir-3-4-non-fault-c/coverages-sfalse-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/glusterfs/workdir-3-4-non-fault-c/coverages-sfalse-ctrue)' using ($1):($8/6) title '' with lp ls c,\
	'<(cnt=$(head -n 25920 fuzzing-dir/eval/glusterfs/workdir-3-4-non-fault-s/coverages-strue-cfalse | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/glusterfs/workdir-3-4-non-fault-s/coverages-strue-cfalse)' using ($1):($8/6) title '' with lp ls s,\
    '<(cnt=$(head -n 25920 fuzzing-dir/eval/glusterfs/workdir-3-4-non-fault-cs/coverages-strue-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/glusterfs/workdir-3-4-non-fault-cs/coverages-strue-ctrue)' using ($1):($8/6) title '' with lp ls cs

# BeeGFS
eval mpNext
unset ylabel
unset xlabel
set title '(b) BeeGFS'
#set ytics 2
#set xtics 8
if ( file_exists("fuzzing-dir/eval/beegfs/workdir-3-4-non-fault-cs/coverages-strue-ctrue") && file_exists("fuzzing-dir/eval/beegfs/workdir-3-4-non-fault-s/coverages-strue-cfalse") && file_exists("fuzzing-dir/eval/beegfs/workdir-3-4-non-fault-c/coverages-sfalse-ctrue")) \
plot '<(cnt=$(head -n 17280 fuzzing-dir/eval/beegfs/workdir-3-4-non-fault-c/coverages-sfalse-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/beegfs/workdir-3-4-non-fault-c/coverages-sfalse-ctrue)' using ($1):($8/6) title '' with lp ls c,\
	'<(cnt=$(head -n 17280 fuzzing-dir/eval/beegfs/workdir-3-4-non-fault-s/coverages-strue-cfalse | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/beegfs/workdir-3-4-non-fault-s/coverages-strue-cfalse)' using ($1):($8/6) title '' with lp ls s,\
    '<(cnt=$(head -n 17280 fuzzing-dir/eval/beegfs/workdir-3-4-non-fault-cs/coverages-strue-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/beegfs/workdir-3-4-non-fault-cs/coverages-strue-ctrue)' using ($1):($8/6) title '' with lp ls cs

# CephFS
eval mpNext
unset ylabel
unset xlabel
# set ylabel 'Branch cov (10K)'
set title '(c) CephFS'
#set ytics 2
if ( file_exists("fuzzing-dir/eval/cephfs/workdir-3-4-non-fault-c/coverages-sfalse-ctrue") && file_exists("fuzzing-dir/eval/cephfs/workdir-3-4-non-fault-s/coverages-strue-cfalse") && file_exists("fuzzing-dir/eval/cephfs/workdir-3-4-non-fault-cs/coverages-strue-ctrue")) \
plot '<(cnt=$(head -n 17280 fuzzing-dir/eval/cephfs/workdir-3-4-non-fault-c/coverages-sfalse-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/cephfs/workdir-3-4-non-fault-c/coverages-sfalse-ctrue)' using ($1):($8/6) title '' with lp ls c,\
	'<(cnt=$(head -n 17280 fuzzing-dir/eval/cephfs/workdir-3-4-non-fault-s/coverages-strue-cfalse | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/cephfs/workdir-3-4-non-fault-s/coverages-strue-cfalse)' using ($1):($8/6) title '' with lp ls s,\
    '<(cnt=$(head -n 17280 fuzzing-dir/eval/cephfs/workdir-3-4-non-fault-cs/coverages-strue-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/cephfs/workdir-3-4-non-fault-cs/coverages-strue-ctrue)' using ($1):($8/6) title '' with lp ls cs

# OrangeFS
eval mpNext
unset ylabel
unset xlabel
set title '(d) OrangeFS'
#set ytics 0.5
#set key at 48,0.8
#set key samplen 2
if ( file_exists("fuzzing-dir/eval/orangefs/workdir-3-4-non-fault-c/coverages-sfalse-ctrue") && file_exists("fuzzing-dir/eval/orangefs/workdir-3-4-non-fault-s/coverages-strue-cfalse") && file_exists("fuzzing-dir/eval/orangefs/workdir-3-4-non-fault-cs/coverages-strue-ctrue")) \
plot '<(cnt=$(head -n 17280 fuzzing-dir/eval/orangefs/workdir-3-4-non-fault-c/coverages-sfalse-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/orangefs/workdir-3-4-non-fault-c/coverages-sfalse-ctrue)' using ($1):($8/6) title '' with lp ls c,\
	'<(cnt=$(head -n 17280 fuzzing-dir/eval/orangefs/workdir-3-4-non-fault-s/coverages-strue-cfalse | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/orangefs/workdir-3-4-non-fault-s/coverages-strue-cfalse)' using ($1):($8/6) title '' with lp ls s,\
    '<(cnt=$(head -n 17280 fuzzing-dir/eval/orangefs/workdir-3-4-non-fault-cs/coverages-strue-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/orangefs/workdir-3-4-non-fault-cs/coverages-strue-ctrue)' using ($1):($8/6) title '' with lp ls cs

# NFS
eval mpNext
unset ylabel
unset xlabel
# set ylabel 'Branch cov (10K)'
# set xlabel 'Time (1 minute)'
set title '(e) NFS'
#set ytics 0.5
#set key at 48,0.6
#set key samplen 2
if ( file_exists("fuzzing-dir/eval/nfs/workdir-1-2-non-fault-c/coverages-sfalse-ctrue") && file_exists("fuzzing-dir/eval/nfs/workdir-1-2-non-fault-cs/coverages-strue-ctrue") && file_exists("fuzzing-dir/eval/nfs/workdir-1-2-non-fault-s/coverages-strue-cfalse")) \
plot '<(cnt=$(head -n 17280 fuzzing-dir/eval/nfs/workdir-1-2-non-fault-c/coverages-sfalse-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/nfs/workdir-1-2-non-fault-c/coverages-sfalse-ctrue)' using ($1):($8/6) title '' with lp ls c,\
	'<(cnt=$(head -n 17280 fuzzing-dir/eval/nfs/workdir-1-2-non-fault-s/coverages-strue-cfalse | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/nfs/workdir-1-2-non-fault-s/coverages-strue-cfalse)' using ($1):($8/6) title '' with lp ls s,\
    '<(cnt=$(head -n 17280 fuzzing-dir/eval/nfs/workdir-1-2-non-fault-cs/coverages-strue-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/nfs/workdir-1-2-non-fault-cs/coverages-strue-ctrue)' using ($1):($8/6) title '' with lp ls cs

# Lustre
eval mpNext
unset ylabel
set title '(f) Lustre'
# set ytics 0.5
unset xlabel
set key samplen 1
set key at 48,0.6
# set xtics 12
if ( file_exists("fuzzing-dir/eval/lustre/workdir-3-4-non-fault-c/coverages-sfalse-ctrue") && file_exists("fuzzing-dir/eval/lustre/workdir-3-4-non-fault-s/coverages-strue-cfalse") && file_exists("fuzzing-dir/eval/lustre/workdir-3-4-non-fault-cs/coverages-strue-ctrue")) \
plot '<(cnt=$(head -n 17280 fuzzing-dir/eval/lustre/workdir-3-4-non-fault-c/coverages-sfalse-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/lustre/workdir-3-4-non-fault-c/coverages-sfalse-ctrue)' using ($1):($8/6) title '' with lp ls c,\
	'<(cnt=$(head -n 17280 fuzzing-dir/eval/lustre/workdir-3-4-non-fault-s/coverages-strue-cfalse | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/lustre/workdir-3-4-non-fault-s/coverages-strue-cfalse)' using ($1):($8/6) title '' with lp ls s,\
    '<(cnt=$(head -n 17280 fuzzing-dir/eval/lustre/workdir-3-4-non-fault-cs/coverages-strue-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/lustre/workdir-3-4-non-fault-cs/coverages-strue-ctrue)' using ($1):($8/6) title '' with lp ls cs


# GlusterFS
eval mpNext
# set ylabel 'Branch cov (10K)'
unset title
set xlabel 'Time (1 minute)'
# set title '(a) GlusterFS'
# set ytics 5
set format y "%.1f"
# set xtics 12
set key at 70,11
if ( file_exists("fuzzing-dir/eval/glusterfs/workdir-3-4-fault-c/coverages-sfalse-ctrue") && file_exists("fuzzing-dir/eval/glusterfs/workdir-3-4-fault-s/coverages-strue-cfalse") && file_exists("fuzzing-dir/eval/glusterfs/workdir-3-4-fault-cs/coverages-strue-ctrue")) \
plot '<(cnt=$(head -n 25920 fuzzing-dir/eval/glusterfs/workdir-3-4-fault-c/coverages-sfalse-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/glusterfs/workdir-3-4-fault-c/coverages-sfalse-ctrue)' using ($1):($8/6) title '' with lp ls c,\
	'<(cnt=$(head -n 25920 fuzzing-dir/eval/glusterfs/workdir-3-4-fault-s/coverages-strue-cfalse | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/glusterfs/workdir-3-4-fault-s/coverages-strue-cfalse)' using ($1):($8/6) title '' with lp ls s,\
    '<(cnt=$(head -n 25920 fuzzing-dir/eval/glusterfs/workdir-3-4-fault-cs/coverages-strue-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/glusterfs/workdir-3-4-fault-cs/coverages-strue-ctrue)' using ($1):($8/6) title '' with lp ls cs

# BeeGFS
eval mpNext
unset ylabel
# set xtics 8
# set title '(b) BeeGFS'
# set ytics 3
if ( file_exists("fuzzing-dir/eval/beegfs/workdir-3-4-fault-c/coverages-sfalse-ctrue") && file_exists("fuzzing-dir/eval/beegfs/workdir-3-4-fault-s/coverages-strue-cfalse") && file_exists("fuzzing-dir/eval/beegfs/workdir-3-4-fault-cs/coverages-strue-ctrue")) \
plot '<(cnt=$(head -n 17280 fuzzing-dir/eval/beegfs/workdir-3-4-fault-c/coverages-sfalse-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/beegfs/workdir-3-4-fault-c/coverages-sfalse-ctrue)' using ($1):($8/6) title '' with lp ls c,\
	'<(cnt=$(head -n 17280 fuzzing-dir/eval/beegfs/workdir-3-4-fault-s/coverages-strue-cfalse | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/beegfs/workdir-3-4-fault-s/coverages-strue-cfalse)' using ($1):($8/6) title '' with lp ls s,\
    '<(cnt=$(head -n 17280 fuzzing-dir/eval/beegfs/workdir-3-4-fault-cs/coverages-strue-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/beegfs/workdir-3-4-fault-cs/coverages-strue-ctrue)' using ($1):($8/6) title '' with lp ls cs

# CephFS
eval mpNext
unset ylabel
# set ylabel 'Branch cov (10K)'
# set title '(c) CephFS'
# set ytics 4
if ( file_exists("fuzzing-dir/eval/cephfs/workdir-3-4-fault-c/coverages-sfalse-ctrue") && file_exists("fuzzing-dir/eval/cephfs/workdir-3-4-fault-s/coverages-strue-cfalse") && file_exists("fuzzing-dir/eval/cephfs/workdir-3-4-fault-cs/coverages-strue-ctrue")) \
plot '<(cnt=$(head -n 17280 fuzzing-dir/eval/cephfs/workdir-3-4-fault-c/coverages-sfalse-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/cephfs/workdir-3-4-fault-c/coverages-sfalse-ctrue)' using ($1):($8/6) title '' with lp ls c,\
	'<(cnt=$(head -n 17280 fuzzing-dir/eval/cephfs/workdir-3-4-fault-s/coverages-strue-cfalse | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/cephfs/workdir-3-4-fault-s/coverages-strue-cfalse)' using ($1):($8/6) title '' with lp ls s,\
    '<(cnt=$(head -n 17280 fuzzing-dir/eval/cephfs/workdir-3-4-fault-cs/coverages-strue-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/cephfs/workdir-3-4-fault-cs/coverages-strue-ctrue)' using ($1):($8/6) title '' with lp ls cs



# OrangeFS
eval mpNext
unset ylabel
# set title '(d) OrangeFS'
# set ytics 1
if ( file_exists("fuzzing-dir/eval/orangefs/workdir-3-4-fault-c/coverages-sfalse-ctrue") && file_exists("fuzzing-dir/eval/orangefs/workdir-3-4-fault-s/coverages-strue-cfalse") && file_exists("fuzzing-dir/eval/orangefs/workdir-3-4-fault-cs/coverages-strue-ctrue")) \
plot '<(cnt=$(head -n 17280 fuzzing-dir/eval/orangefs/workdir-3-4-fault-c/coverages-sfalse-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/orangefs/workdir-3-4-fault-c/coverages-sfalse-ctrue)' using ($1):($8/6) title '' with lp ls c,\
	'<(cnt=$(head -n 17280 fuzzing-dir/eval/orangefs/workdir-3-4-fault-s/coverages-strue-cfalse | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/orangefs/workdir-3-4-fault-s/coverages-strue-cfalse)' using ($1):($8/6) title '' with lp ls s,\
    '<(cnt=$(head -n 17280 fuzzing-dir/eval/orangefs/workdir-3-4-fault-cs/coverages-strue-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/orangefs/workdir-3-4-fault-cs/coverages-strue-ctrue)' using ($1):($8/6) title '' with lp ls cs

# NFS
eval mpNext
unset ylabel
# set ylabel 'Branch cov (10K)'
set xlabel 'Time (1 minute)'
# set title '(e) NFS'
# set ytics 0.5
if ( file_exists("fuzzing-dir/eval/nfs/workdir-1-2-fault-c/coverages-sfalse-ctrue") && file_exists("fuzzing-dir/eval/nfs/workdir-1-2-fault-cs/coverages-strue-ctrue") && file_exists("fuzzing-dir/eval/nfs/workdir-1-2-fault-s/coverages-strue-cfalse")) \
plot '<(cnt=$(head -n 17280 fuzzing-dir/eval/nfs/workdir-1-2-fault-c/coverages-sfalse-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/nfs/workdir-1-2-fault-c/coverages-sfalse-ctrue)' using ($1):($8/6) title '' with lp ls c,\
	'<(cnt=$(head -n 17280 fuzzing-dir/eval/nfs/workdir-1-2-fault-s/coverages-strue-cfalse | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/nfs/workdir-1-2-fault-s/coverages-strue-cfalse)' using ($1):($8/6) title '' with lp ls s,\
    '<(cnt=$(head -n 17280 fuzzing-dir/eval/nfs/workdir-1-2-fault-cs/coverages-strue-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/nfs/workdir-1-2-fault-cs/coverages-strue-ctrue)' using ($1):($8/6) title '' with lp ls cs

# Lustre
eval mpNext
unset ylabel
# set title '(f) Lustre'
# set xtics 8
# set ytics 0.4
if ( file_exists("fuzzing-dir/eval/lustre/workdir-3-4-fault-c/coverages-sfalse-ctrue") && file_exists("fuzzing-dir/eval/lustre/workdir-3-4-fault-s/coverages-strue-cfalse") && file_exists("fuzzing-dir/eval/lustre/workdir-3-4-fault-cs/coverages-strue-ctrue")) \
plot '<(cnt=$(head -n 17280 fuzzing-dir/eval/lustre/workdir-3-4-fault-c/coverages-sfalse-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/lustre/workdir-3-4-fault-c/coverages-sfalse-ctrue)' using ($1):($8/6) title '' with lp ls c,\
	'<(cnt=$(head -n 17280 fuzzing-dir/eval/lustre/workdir-3-4-fault-s/coverages-strue-cfalse | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/lustre/workdir-3-4-fault-s/coverages-strue-cfalse)' using ($1):($8/6) title '' with lp ls s,\
    '<(cnt=$(head -n 17280 fuzzing-dir/eval/lustre/workdir-3-4-fault-cs/coverages-strue-ctrue | wc -l);step=$(( cnt / 10 )) ; sed -n "1~${step}p" fuzzing-dir/eval/lustre/workdir-3-4-fault-cs/coverages-strue-ctrue)' using ($1):($8/6) title '' with lp ls cs
