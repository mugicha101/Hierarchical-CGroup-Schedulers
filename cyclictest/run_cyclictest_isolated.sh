secs=${1:-10}
echo "Running cyclictest for $secs seconds"

sudo ./cyclictest_common.sh "$secs"
sudo sh ./isolate_cpus_end.sh
