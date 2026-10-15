secs=${1:-10}
sudo rm -f trace.perfetto
sudo killall -9 -r '^tracebox'
TRACE_PID=$(sudo ./tracebox --background-wait -c ./perfetto_config.pbtx --txt -o trace.perfetto)
echo $TRACE_PID

echo "Waiting 5 seconds for tracebox setup to finish"
sleep 5
echo "Running cyclictest for $secs seconds"

sudo ./cyclictest_common.sh "$secs"

sudo kill -SIGINT $TRACE_PID
echo "Waiting for tracebox to finish..."
while sudo kill -0 $TRACE_PID 2>/dev/null; do
    sleep 0.5
done
sudo chown $USER:$USER trace.perfetto

# prevent viewlogs from seeing a bunch of junk enabled for tracebox
echo "Reseting tracing settings"
TRACING_DIR="/sys/kernel/debug/tracing"
echo 0 | sudo tee "$TRACING_DIR/tracing_on"> /dev/null
echo nop | sudo tee "$TRACING_DIR/current_tracer"> /dev/null
echo | sudo tee "$TRACING_DIR/set_event"> /dev/null
echo | sudo tee "$TRACING_DIR/set_ftrace_filter" 2>/dev/null
echo | sudo tee "$TRACING_DIR/set_ftrace_notrace" 2>/dev/null
echo | sudo tee "$TRACING_DIR/set_ftrace_pid" 2>/dev/null
echo | sudo tee "$TRACING_DIR/set_event_pid" 2>/dev/null
echo | sudo tee "$TRACING_DIR/trace" > /dev/null
echo 1 | sudo tee "$TRACING_DIR/tracing_on"> /dev/null
