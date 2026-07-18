LOOPS=${1:-10000}
echo "COMPILING" && \
gcc ./mig_program.c -o mig_program -lpthread -lrt && \
echo "RUNNING" && \
sudo trace-cmd record -e sched_migrate_task -e sched_switch ./mig_program "$LOOPS" > mig_program_output.txt 2>&1 && \
echo "EXPORTING" && \
trace-cmd report -t --ts-check > trace_report.txt && \
echo "ANALYZING" && \
python3 ./mig_trace_analyze.py mig_program > ./mig_latency_results.txt 2>&1 && \
echo "VISUALIZING" && \
python3 ./mig_viz.py && \
echo "DONE"