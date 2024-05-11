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

# GlusterFS
eval mpNext
set ylabel 'Branch cov (10K)' offset 0,-2.9
unset xlabel
set title '(a) GlusterFS'
set format y "%.1f"
set ytics 1.5
set xtics 12
set key at 72,2.5
plot "fuzzing-dir/cov/non-fault/glusterfs/coverages-sfalse-ctrue" using ($1/360):($8/10000) title '' with lp ls c,\
	"fuzzing-dir/cov/non-fault/glusterfs/coverages-strue-cfalse" using ($1/360):($8/10000) title '' with lp ls s,\
    "fuzzing-dir/cov/non-fault/glusterfs/coverages-strue-ctrue" using ($1/360):($8/10000) title '' with lp ls cs

# BeeGFS
eval mpNext
unset ylabel
unset xlabel
set title '(b) BeeGFS'
set ytics 2
set xtics 8
plot "fuzzing-dir/cov/non-fault/beegfs/coverages-sfalse-ctrue" using ($1/360):($8/10000) title '' with lp ls c,\
	"fuzzing-dir/cov/non-fault/beegfs/coverages-strue-cfalse" using ($1/360):($8/10000) title '' with lp ls s,\
    "fuzzing-dir/cov/non-fault/beegfs/coverages-strue-ctrue" using ($1/360):($8/10000) title '' with lp ls cs

# CephFS
eval mpNext
unset ylabel
unset xlabel
# set ylabel 'Branch cov (10K)'
set title '(c) CephFS'
set ytics 2
plot "fuzzing-dir/cov/non-fault/cephfs/coverages-sfalse-ctrue" using ($1/360):($8/10000) title '' with lp ls c,\
	"fuzzing-dir/cov/non-fault/cephfs/coverages-strue-cfalse" using ($1/360):($8/10000) title '' with lp ls s,\
    "fuzzing-dir/cov/non-fault/cephfs/coverages-strue-ctrue" using ($1/360):($8/10000) title '' with lp ls cs

# OrangeFS
eval mpNext
unset ylabel
unset xlabel
set title '(d) OrangeFS'
set ytics 0.5
set key at 48,0.8
set key samplen 2
plot "fuzzing-dir/cov/non-fault/orangefs/coverages-sfalse-ctrue" using ($1/360):($8/10000) title 'client' with lp ls c,\
	"fuzzing-dir/cov/non-fault/orangefs/coverages-strue-cfalse" using ($1/360):($8/10000) title '' with lp ls s,\
    "fuzzing-dir/cov/non-fault/orangefs/coverages-strue-ctrue" using ($1/360):($8/10000) title '' with lp ls cs

# NFS
eval mpNext
unset ylabel
unset xlabel
# set ylabel 'Branch cov (10K)'
# set xlabel 'Time (1 hour)'
set title '(e) NFS'
set ytics 0.5
set key at 48,0.6
set key samplen 2
plot "fuzzing-dir/cov/non-fault/nfs/coverages-sfalse-ctrue" using ($1/360):($8/10000) title '' with lp ls c,\
	"fuzzing-dir/cov/non-fault/nfs/coverages-strue-cfalse" using ($1/360):($8/10000) title 'server' with lp ls s,\
    "fuzzing-dir/cov/non-fault/nfs/coverages-strue-ctrue" using ($1/360):($8/10000) title '' with lp ls cs

# Lustre
eval mpNext
unset ylabel
set title '(f) Lustre'
set ytics 0.5
unset xlabel
set key samplen 1
set key at 48,0.6
# set xtics 12
plot "fuzzing-dir/cov/non-fault/lustre/coverages-sfalse-ctrue" using ($1/360):($8/10000) title '' with lp ls c,\
	"fuzzing-dir/cov/non-fault/lustre/coverages-strue-cfalse" using ($1/360):($8/10000) title '' with lp ls s,\
    "fuzzing-dir/cov/non-fault/lustre/coverages-strue-ctrue" using ($1/360):($8/10000) title 'server+client' with lp ls cs

# GlusterFS
eval mpNext
# set ylabel 'Branch cov (10K)'
unset title
set xlabel 'Time (1 hour)'
# set title '(a) GlusterFS'
set ytics 5
set format y "%.1f"
set xtics 12
set key at 70,11
plot "fuzzing-dir/cov/fault/glusterfs/coverages-sfalse-ctrue" using ($1/360):($8/10000) title '' with lp ls c,\
	"fuzzing-dir/cov/fault/glusterfs/coverages-strue-cfalse" using ($1/360):($8/10000) title '' with lp ls s,\
    "fuzzing-dir/cov/fault/glusterfs/coverages-strue-ctrue" using ($1/360):($8/10000) title '' with lp ls cs

# BeeGFS
eval mpNext
unset ylabel
set xtics 8
# set title '(b) BeeGFS'
set ytics 3
plot "fuzzing-dir/cov/fault/beegfs/coverages-sfalse-ctrue" using ($1/360):($8/10000) title '' with lp ls c,\
	"fuzzing-dir/cov/fault/beegfs/coverages-strue-cfalse" using ($1/360):($8/10000) title '' with lp ls s,\
    "fuzzing-dir/cov/fault/beegfs/coverages-strue-ctrue" using ($1/360):($8/10000) title '' with lp ls cs

# CephFS
eval mpNext
unset ylabel
# set ylabel 'Branch cov (10K)'
# set title '(c) CephFS'
set ytics 4
plot "fuzzing-dir/cov/fault/cephfs/coverages-sfalse-ctrue" using ($1/360):($8/10000) title '' with lp ls c,\
	"fuzzing-dir/cov/fault/cephfs/coverages-strue-cfalse" using ($1/360):($8/10000) title '' with lp ls s,\
    "fuzzing-dir/cov/fault/cephfs/coverages-strue-ctrue" using ($1/360):($8/10000) title '' with lp ls cs



# OrangeFS
eval mpNext
unset ylabel
# set title '(d) OrangeFS'
set ytics 1
plot "fuzzing-dir/cov/fault/orangefs/coverages-sfalse-ctrue" using ($1/360):($8/10000) title '' with lp ls c,\
	"fuzzing-dir/cov/fault/orangefs/coverages-strue-cfalse" using ($1/360):($8/10000) title '' with lp ls s,\
    "fuzzing-dir/cov/fault/orangefs/coverages-strue-ctrue" using ($1/360):($8/10000) title '' with lp ls cs

# NFS
eval mpNext
unset ylabel
# set ylabel 'Branch cov (10K)'
set xlabel 'Time (1 hour)'
# set title '(e) NFS'
set ytics 0.5
plot "fuzzing-dir/cov/fault/nfs/coverages-sfalse-ctrue" using ($1/360):($8/10000) title '' with lp ls c,\
	"fuzzing-dir/cov/fault/nfs/coverages-strue-cfalse" using ($1/360):($8/10000) title '' with lp ls s,\
    "fuzzing-dir/cov/fault/nfs/coverages-strue-ctrue" using ($1/360):($8/10000) title '' with lp ls cs

# Lustre
eval mpNext
unset ylabel
# set title '(f) Lustre'
#set xtics 8
set ytics 0.4
plot "fuzzing-dir/cov/fault/lustre/coverages-sfalse-ctrue" using ($1/360):($8/10000) title '' with lp ls c,\
	"fuzzing-dir/cov/fault/lustre/coverages-strue-cfalse" using ($1/360):($8/10000) title '' with lp ls s,\
    "fuzzing-dir/cov/fault/lustre/coverages-strue-ctrue" using ($1/360):($8/10000) title '' with lp ls cs
