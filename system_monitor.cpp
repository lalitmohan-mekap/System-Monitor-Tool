// system_monitor.cpp
// Minimal system monitor reading from /proc.
// Build: g++ -std=c++17 -O2 -o system_monitor system_monitor.cpp

#include <bits/stdc++.h>
#include <dirent.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/select.h>

using namespace std;

struct ProcStatSample {
    unsigned long long total_jiffies;
    unsigned long long idle_jiffies;
};

struct Process {
    int pid = 0;
    string user;
    string cmd;
    unsigned long long utime = 0;
    unsigned long long stime = 0;
    unsigned long long total_time() const { return utime + stime; }
    long rss_kb = 0;
    double cpu_percent = 0.0;
    double mem_percent = 0.0;
};

enum SortMode { BY_CPU, BY_MEM, BY_PID };

static long Hertz = sysconf(_SC_CLK_TCK);

ProcStatSample read_proc_stat() {
    FILE* f = fopen("/proc/stat", "r");
    ProcStatSample s{0,0};
    if (!f) return s;
    char line[512];
    if (fgets(line, sizeof(line), f)) {
        // first line "cpu  3357 0 4313 1362393 0 0 0 0 0 0"
        unsigned long long user=0, nice=0, system=0, idle=0, iowait=0, irq=0, softirq=0, steal=0;
        // use sscanf to parse many fields; keep it robust
        sscanf(line, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
               &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal);
        s.idle_jiffies = idle + iowait;
        s.total_jiffies = user + nice + system + idle + iowait + irq + softirq + steal;
    }
    fclose(f);
    return s;
}

unsigned long long parse_ull_from_file(const string &path) {
    unsigned long long v=0;
    FILE* f = fopen(path.c_str(), "r");
    if (!f) return 0;
    if (fscanf(f, "%llu", &v) != 1) v = 0;
    fclose(f);
    return v;
}

long get_total_mem_kb() {
    FILE* f = fopen("/proc/meminfo", "r");
    long total = 0;
    if (!f) return 0;
    char key[128];
    long val;
    while (fscanf(f, "%127s %ld", key, &val) == 2) {
        string k(key);
        if (k.rfind("MemTotal:", 0) == 0) {
            total = val; // kB
            break;
        }
    }
    fclose(f);
    return total;
}

string uid_to_user(uid_t uid) {
    passwd *pw = getpwuid(uid);
    if (pw) return string(pw->pw_name);
    return to_string(uid);
}

bool is_number(const char* s) {
    while (*s) {
        if (!isdigit(*s)) return false;
        ++s;
    }
    return true;
}

Process read_process(int pid, long total_mem_kb) {
    Process p;
    p.pid = pid;

    // read /proc/[pid]/stat for utime, stime and cmd (stat includes comm in parentheses)
    string statpath = "/proc/" + to_string(pid) + "/stat";
    FILE* f = fopen(statpath.c_str(), "r");
    if (!f) return p;

    // stat format: pid (comm) state ppid ... utime stime cutime cstime ...
    // We'll parse specially: read whole line then parse fields around parentheses.
    char buf[8192];
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return p; }
    fclose(f);
    string line(buf);
    // find '(' and ')' to extract cmd
    auto lparen = line.find('(');
    auto rparen = line.rfind(')');
    if (lparen != string::npos && rparen != string::npos && rparen > lparen) {
        p.cmd = line.substr(lparen + 1, rparen - lparen - 1);
    } else {
        p.cmd = "?";
    }
    // tokenize after rparen
    string after = line.substr(rparen + 2); // skip ") "
    // fields: state(1), ppid(2), ... utime is field 13 after pid including comm. Simpler: use stringstream
    stringstream ss(after);
    string token;
    vector<string> fields;
    while (ss >> token) fields.push_back(token);
    // utime is fields[11] (since after rparen we started at field 3 original, but using indexes it's consistent)
    // According to proc man: utime is 14th field overall, stime 15th. After rparen we've skipped first 2 fields (state and ppid),
    // safe method: convert by counting. But empirically fields[11] = utime, fields[12] = stime.
    if (fields.size() > 12) {
        p.utime = stoull(fields[11]);
        p.stime = stoull(fields[12]);
    }

    // read /proc/[pid]/status for Uid and VmRSS
    string statuspath = "/proc/" + to_string(pid) + "/status";
    FILE* fs = fopen(statuspath.c_str(), "r");
    if (fs) {
        char key[256];
        while (fscanf(fs, "%255s", key) == 1) {
            if (strcmp(key, "Uid:") == 0) {
                int real, eff, saved, fsuid;
                if (fscanf(fs, "%d %d %d %d", &real, &eff, &saved, &fsuid) == 4) {
                    p.user = uid_to_user(real);
                }
            } else if (strcmp(key, "VmRSS:") == 0) {
                long rss = 0; // kB
                if (fscanf(fs, "%ld", &rss) == 1) {
                    p.rss_kb = rss;
                }
            } else {
                // skip rest of line
                char rest[512];
                fgets(rest, sizeof(rest), fs);
            }
        }
        fclose(fs);
    }

    // If we didn't find rss in status (some processes), try statm
    if (p.rss_kb == 0) {
        string statmpath = "/proc/" + to_string(pid) + "/statm";
        FILE* fm = fopen(statmpath.c_str(), "r");
        if (fm) {
            unsigned long size, rss_pages;
            if (fscanf(fm, "%lu %lu", &size, &rss_pages) >= 2) {
                long page_kb = sysconf(_SC_PAGESIZE) / 1024;
                p.rss_kb = rss_pages * page_kb;
            }
            fclose(fm);
        }
    }

    // fallback user
    if (p.user.empty()) {
        // stat to get uid
        struct stat st;
        string procPath = "/proc/" + to_string(pid);
        if (stat(procPath.c_str(), &st) == 0) {
            p.user = uid_to_user(st.st_uid);
        } else {
            p.user = "n/a";
        }
    }

    // mem percent computed later using total_mem_kb
    if (total_mem_kb > 0) {
        p.mem_percent = (100.0 * (double)p.rss_kb) / (double)total_mem_kb;
    } else p.mem_percent = 0.0;

    return p;
}

vector<Process> read_all_processes(long total_mem_kb) {
    vector<Process> procs;
    DIR* dp = opendir("/proc");
    if (!dp) return procs;
    struct dirent* de;
    while ((de = readdir(dp)) != nullptr) {
        if (de->d_type == DT_DIR && is_number(de->d_name)) {
            int pid = atoi(de->d_name);
            Process p = read_process(pid, total_mem_kb);
            if (p.pid != 0) procs.push_back(move(p));
        }
    }
    closedir(dp);
    return procs;
}

// compute CPU% for each process by comparing two snapshots
void compute_cpu_percentages(vector<Process>& cur, const vector<Process>& prev,
                             unsigned long long total_delta_jiffies) {
    unordered_map<int, unsigned long long> prev_map;
    for (const auto &p: prev) prev_map[p.pid] = p.total_time();

    for (auto &p: cur) {
        auto it = prev_map.find(p.pid);
        unsigned long long prev_total = (it != prev_map.end()) ? it->second : 0ULL;
        unsigned long long delta_proc = 0;
        unsigned long long cur_total = p.total_time();
        if (cur_total >= prev_total) delta_proc = cur_total - prev_total;
        else delta_proc = 0;
        if (total_delta_jiffies > 0)
            p.cpu_percent = 100.0 * double(delta_proc) / double(total_delta_jiffies);
        else
            p.cpu_percent = 0.0;
    }
}

void clear_screen() {
    // ANSI clear screen
    cout << "\033[2J\033[H";
}

void print_header(double system_cpu_load, long total_mem_kb, long free_mem_kb, int nprocs, int refresh_s) {
    cout << "System Monitor Tool  |  refresh: " << refresh_s << "s"
         << "  | procs: " << nprocs << "\n";
    cout << fixed << setprecision(1);
    cout << "CPU Load: " << system_cpu_load << "%   ";
    cout << "Mem: " << ((total_mem_kb - free_mem_kb)/1024) << "MB/" << (total_mem_kb/1024) << "MB\n";
    cout << left << setw(6) << "PID" << setw(10) << "USER" << setw(7) << "CPU%" << setw(7) << "MEM%" << setw(10) << "RSS" << "COMMAND" << "\n";
    cout << string(80, '-') << "\n";
}

void print_processes(const vector<Process>& procs, int maxrows=20) {
    int count = 0;
    cout.setf(ios::fixed); cout<<setprecision(1);
    for (const auto &p: procs) {
        cout << setw(6) << p.pid
             << setw(10) << (p.user.size()<=9 ? p.user : p.user.substr(0,9))
             << setw(7) << p.cpu_percent
             << setw(7) << p.mem_percent
             << setw(10) << p.rss_kb
             << p.cmd << "\n";
        if (++count >= maxrows) break;
    }
}

// safe kill function: first SIGTERM, then SIGKILL if required
bool kill_process(int pid) {
    if (kill(pid, SIGTERM) == 0) {
        // give brief time then check
        usleep(200000); // 200ms
        if (kill(pid, 0) == -1) return true; // process gone
        // else try SIGKILL
        if (kill(pid, SIGKILL) == 0) return true;
        return false;
    } else {
        return false;
    }
}

int main() {
    // parameters
    int refresh_seconds = 2;
    SortMode sort_mode = BY_CPU;

    // initial samples
    ProcStatSample prev_stat = read_proc_stat();
    long total_mem_kb = get_total_mem_kb();
    vector<Process> prev_procs = read_all_processes(total_mem_kb);

    // Prepare stdin nonblocking? We'll use select() to wait with timeout and allow input.
    // main loop
    bool running = true;
    while (running) {
        sleep(1); // minor pause to avoid tight loop when starting (we'll use select below)
        // take new snapshot
        ProcStatSample cur_stat = read_proc_stat();
        unsigned long long delta_total = 0;
        if (cur_stat.total_jiffies >= prev_stat.total_jiffies)
            delta_total = cur_stat.total_jiffies - prev_stat.total_jiffies;
        else delta_total = 0;

        total_mem_kb = get_total_mem_kb();
        vector<Process> cur_procs = read_all_processes(total_mem_kb);

        // compute per-process CPU% using jiffies delta (process jiffies are in clock ticks)
        compute_cpu_percentages(cur_procs, prev_procs, delta_total);

        // compute system CPU load as percent busy (1 - idle_delta/total_delta)
        double sys_cpu_load = 0.0;
        unsigned long long idle_delta = 0;
        if (cur_stat.idle_jiffies >= prev_stat.idle_jiffies) idle_delta = cur_stat.idle_jiffies - prev_stat.idle_jiffies;
        if (delta_total > 0) sys_cpu_load = 100.0 * double(delta_total - idle_delta) / double(delta_total);

        // sort processes
        if (sort_mode == BY_CPU) {
            sort(cur_procs.begin(), cur_procs.end(), [](const Process& a, const Process& b){
                if (a.cpu_percent == b.cpu_percent) return a.pid < b.pid;
                return a.cpu_percent > b.cpu_percent;
            });
        } else if (sort_mode == BY_MEM) {
            sort(cur_procs.begin(), cur_procs.end(), [](const Process& a, const Process& b){
                if (a.mem_percent == b.mem_percent) return a.pid < b.pid;
                return a.mem_percent > b.mem_percent;
            });
        } else {
            sort(cur_procs.begin(), cur_procs.end(), [](const Process& a, const Process& b){
                return a.pid < b.pid;
            });
        }

        // display
        clear_screen();
        // mem free estimate from /proc/meminfo: get MemFree value quickly
        long mem_free_kb = 0;
        {
            FILE* fm = fopen("/proc/meminfo", "r");
            if (fm) {
                char key[128];
                long val;
                while (fscanf(fm, "%127s %ld", key, &val) == 2) {
                    string k(key);
                    if (k.rfind("MemFree:", 0) == 0) { mem_free_kb = val; break; }
                }
                fclose(fm);
            }
        }

        print_header(sys_cpu_load, total_mem_kb, mem_free_kb, (int)cur_procs.size(), refresh_seconds);
        print_processes(cur_procs, 40);
        cout << "\nCommands: k <pid>  |  s cpu|mem|pid  |  q\n";
        cout << "Enter command: " << flush;

        // wait for input with timeout = refresh_seconds
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(0, &readfds); // stdin
        struct timeval tv;
        tv.tv_sec = refresh_seconds;
        tv.tv_usec = 0;
        int sel = select(1, &readfds, NULL, NULL, &tv);
        if (sel > 0 && FD_ISSET(0, &readfds)) {
            string line;
            if (!getline(cin, line)) { running = false; break; }
            // parse command
            stringstream ss(line);
            string cmd;
            ss >> cmd;
            if (cmd == "q" || cmd == "quit") {
                running = false;
            } else if (cmd == "k") {
                int pid; ss >> pid;
                if (pid <= 0) {
                    cout << "Invalid pid\n";
                    usleep(800000);
                } else {
                    cout << "Killing " << pid << " ... " << flush;
                    bool ok = kill_process(pid);
                    cout << (ok ? "OK\n" : "FAILED\n");
                    usleep(800000);
                }
            } else if (cmd == "s") {
                string mode; ss >> mode;
                if (mode == "cpu") sort_mode = BY_CPU;
                else if (mode == "mem") sort_mode = BY_MEM;
                else if (mode == "pid") sort_mode = BY_PID;
                else {
                    cout << "Unknown sort mode\n";
                    usleep(600000);
                }
            } else if (cmd.empty()) {
                // nothing
            } else {
                cout << "Unknown command\n";
                usleep(600000);
            }
        } else {
            // no input; timed out => continue refresh
        }

        // rotate snapshots
        prev_stat = cur_stat;
        prev_procs = move(cur_procs);
    }

    cout << "\nExiting system monitor.\n";
    return 0;
}
