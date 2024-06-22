import subprocess,os
import numpy
import matplotlib.pyplot as plt
import sys
import timeit

NUM_SAMPLES = 5
EXEC_TIME_LABEL = "Elapsed (wall clock) time (h:mm:ss or m:ss): 0:"
MAX_RSS_LABEL="Maximum resident set size (kbytes):"


EXEC_COMMANDS={"httpd":["t/TEST","-httpd /home/rahultgeorge/Desktop/httpd/httpd"],
               "sqlite3":["./testfixture" ,"/home/rahultgeorge/Desktop/sqlite/test/quick.test"],
               "redis":["make","test"],
               "openssl":["make","TESTS='-test_ecparam'","test"],
               "libxml2":["make","tests"]}

def execute_program():
    global NUM_SAMPLES
    exec_times = []
    final_max_rss = []
    final_exec_times = []

    for _ in range(NUM_SAMPLES):
        exec_stats = subprocess.run(
            ["/usr/bin/time","-v", "t/TEST","-httpd /home/rahultgeorge/Desktop/httpd/httpd"], capture_output=True, text=True)
        print(exec_stats)
        exec_stats = exec_stats.stdout + exec_stats.stderr
        # print(exec_stats)
        max_rss=int(exec_stats[exec_stats.index(MAX_RSS_LABEL)+len(MAX_RSS_LABEL)+1:].split()[0])
        # print(max_rss)
        exec_stats = exec_stats.split()
        exec_time = float(exec_stats[exec_stats.index(EXEC_TIME_LABEL) + 1])
        exec_times.append(exec_time)
        final_max_rss.append(max_rss)
        print("Iteration:",exec_time,max_rss)

    exec_standard_deviation = numpy.std(exec_times)
    avg_exec_time = numpy.mean(exec_times)


    max_rss_standard_deviation = numpy.std(final_max_rss)
    final_mean_rss =numpy.mean(final_max_rss)
    print("Metric all samples, AVG, STD")
    print("Exec time info:",exec_times, avg_exec_time, exec_standard_deviation)
    print("Max RSS time info:",final_max_rss, final_mean_rss, max_rss_standard_deviation)

    final_exec_times= exec_times
    final_mean_exec_time = numpy.mean(final_exec_times)

    # # Isn't of dropping samples that deviate by 2*std which may be anything (no real bound wrt execution time)
    # # Wouldn't it be better to drop samples that deviate by more than say 1% of avg execution time
    # # max_allowed_deviation = 0.01 * avg_exec_time
    # max_allowed_deviation = 2 * standard_deviation


    # # plt.hist(exec_times,NUM_SAMPLES)
    # # plt.gca().set(title='Execution Time Frequency Histogram', ylabel='Frequency');
    # # x_axis = [i for i in range(NUM_SAMPLES)]

    # for sample_num in range(NUM_SAMPLES):
    #     # Drop samples (outliers) that deviate from the mean by >=2*standard deviation
    #     if not max_allowed_deviation or abs(exec_times[sample_num] - avg_exec_time) < max_allowed_deviation:
    #         final_exec_times.append(exec_times[sample_num])
    #     else:
    #         # plt.axvline(x=sample_num, color='r')
            # NUM_SAMPLES = NUM_SAMPLES - 1

    # plt.plot(x_axis, exec_times)
    # plt.savefig("exec_times.pdf")

    # print("Avg exec time all samples:",final_mean_exec_time)
    # print("Avg max RSS all samples:",final_mean_rss)

    return final_mean_exec_time, final_mean_rss



def execute_program_old():
    # custom_env = os.environ
    #custom_env = "ASAN_OPTIONS=detect_leaks=0:replace_str=false:replace_intrin=false:intercept_strchr=0:intercept_strndup=0:intercept_strlen=0:halt_on_error=0" + custom_env
    # print("ENV:",custom_env)

    try:
        subprocess.run(
            EXEC_COMMANDS[program_name])
        # print("Exec info:",exec_stats)
    except subprocess.CalledProcessError :
        print("Error: Failed to execute command")
        sys.exit(1)

    # standard_deviation = numpy.std(exec_times)
    # avg_exec_time = numpy.mean(exec_times)

    # print(exec_times, avg_exec_time, standard_deviation)
    # # Isn't of dropping samples that deviate by 2*std which may be anything (no real bound wrt execution time)
    # # Wouldn't it be better to drop samples that deviate by more than say 1% of avg execution time
    # # max_allowed_deviation = 0.01 * avg_exec_time
    # max_allowed_deviation = 2 * standard_deviation

    # final_exec_times = []

    # # plt.hist(exec_times,NUM_SAMPLES)
    # # plt.gca().set(title='Execution Time Frequency Histogram', ylabel='Frequency');
    # # x_axis = [i for i in range(NUM_SAMPLES)]

    # for sample_num in range(NUM_SAMPLES):
    #     # Drop samples (outliers) that deviate from the mean by >=2*standard deviation
    #     if not max_allowed_deviation or abs(exec_times[sample_num] - avg_exec_time) < max_allowed_deviation:
    #         final_exec_times.append(exec_times[sample_num])
    #     else:
    #         # plt.axvline(x=sample_num, color='r')
    #         NUM_SAMPLES = NUM_SAMPLES - 1

    # # plt.plot(x_axis, exec_times)
    # # plt.savefig("exec_times.pdf")
    # final_mean_exec_time = numpy.mean(final_exec_times)
    # print("Avg all samples:",avg_exec_time)
    # return final_mean_exec_time


"""

  export ASAN_OPTIONS=detect_stack_use_after_return=0:halt_on_error=0:detect_leaks=0:replace_str=false:replace_intrin=false:intercept_strchr=0:intercept_strndup=0:intercept_strlen=0:use_sigaltstack=false:print_legend=false:print_full_thread_history=false:check_malloc_usable_size=false:poison_heap=false:poison_array_cookie=false:detect_container_overflow=false:malloc_context_size=0:poison_partial=false:alloc_dealloc_mismatch=false:new_delete_type_mismatch=false:allow_user_poisoning=false:intercept_memcmp=false:check_printf=false
  export OPTISAN_COMPILER_STATE="PlacementMode"
  export OPTISAN_PROGRAM_NAME="xmllint"

"""
if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python3 run_program.py <program_name>")
        # print("Supported: ",EXEC_COMMANDS.keys())
        sys.exit(1)

    program_name=str(sys.argv[1])
    if program_name not in EXEC_COMMANDS:
        print(program_name," not supported")
        sys.exit(1)

    final_avg_exec_time, final_max_rss = execute_program()
    print("AVG execution time over ", NUM_SAMPLES,
          " samples: ", final_avg_exec_time)
    print("AVG Max RSS over ", NUM_SAMPLES,
          " samples: ", final_max_rss)
