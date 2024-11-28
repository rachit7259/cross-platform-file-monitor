#include <iostream>
#include <thread>
#include <fstream>
#include <sstream>
#include "cpp-httplib/httplib.h"
#include <sys/inotify.h>
#include <unordered_map>
#include <ctime>
#include <queue>
#include <mutex>
#include <condition_variable>

using namespace std;

//Config
const int BUFFER_SIZE = 1024 * (sizeof(struct inotify_event) + 16);
const string MONITOR_PATH = "./monitor";

queue<string> fileQueue;
mutex queueMutex;
condition_variable cv;
//bool terminate = false;

unordered_map<string, bool> scanResults;
mutex resultsMutex;

//Logging
void logScanResult(const string &filePath, bool sensitiveDataFound)
{
    ofstream logFile("scan_log.txt", ios::app);

    if(!logFile.is_open())
    {
        cerr << "Failed to open log file." << endl;
        return;
    }

    time_t now = time(nullptr);

    logFile << ctime(&now) << " - File: " << filePath
        << " - Sensitive Content: " << (sensitiveDataFound ? "Yes" : "No") << endl;
}

//DLP logic: mock scanning for sensitive data
bool scanFileForSensitiveData(const string &filePath)
{
    ifstream file(filePath);

    if(!file.is_open())
    {
        cerr << "Failed to open file: " << filePath <<endl;
        return false;
    }

    // Define patterns for sensitive data
    const vector<regex> patterns = {
        regex(R"((\b\d{3}-\d{2}-\d{4}\b))"), // SSN
        regex(R"((\b4[0-9]{12}(?:[0-9]{3}?\b)))"), // Credit Card
        regex(R"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)"), // Email
        regex(R"(\bpassword\b)", regex_constants::icase) //password
    };

    string line;
    
    while (getline(file, line))
    {
        for (const auto &pattern : patterns)
        {
            if (regex_search(line, pattern))
            {
                return true; //Detected sensitive content
            }
        }
    }

    return false; //No sensitive content
}

//Async File Queue for scanning
void enqueueFile(const string &filePath)
{
    lock_guard<mutex> lock(queueMutex);
    fileQueue.push(filePath);
    cout << "File enqueued: " << filePath << endl;
    cv.notify_one();
}

//API endpoints for async file scanning
void enqueueFileApi(const string &filePath)
{
    enqueueFile(filePath);

    lock_guard<mutex> lock(resultsMutex);
    scanResults[filePath] = false;
}

bool getScanResults(const string &filePath)
{
    lock_guard<mutex> lock(resultsMutex);

    if(scanResults.find(filePath) != scanResults.end())
    {
        return scanResults[filePath];
    }

    return false;
}

//Update the results after Processing
void updateScanResult (const string &filePath, bool result)
{
    lock_guard<mutex> lock(resultsMutex);
    scanResults[filePath] = result;
}

void processFileQueue()
{
    while (true)
    {
        string filePath;

        {
            unique_lock<mutex> lock(queueMutex);

            // Wait until the queue is not empty or the program signals termination
            cv.wait(lock, [] {return !fileQueue.empty();});

            // if(terminate)
            //     break;

            // Double-check to avoid issues with spurious wakeups
            if (fileQueue.empty())
                continue;

            filePath = fileQueue.front();
            fileQueue.pop();
        }

        //Process the file with error handling
        try
        {
            bool sensitiveDataFound = scanFileForSensitiveData(filePath);

            cout << "File: " << filePath << " Sensitive data found: " 
                << (sensitiveDataFound ? "Yes" : "No") << endl;

            updateScanResult(filePath, sensitiveDataFound);
            logScanResult(filePath, sensitiveDataFound);
        }
        catch(const exception &e)
        {
            cerr << "Error processing file " << filePath << ": " << e.what() << endl;
        }
        catch(...)
        {
            cerr << "Unknown error processing file " << filePath << endl;
        }

    }
}

//File monitoring function
void monitorFiles()
{
    int fd = inotify_init();

    if (fd < 0)
    {
        cerr << "Failed to initialize notify" << endl;
        return;
    }

    int wd = inotify_add_watch(fd, MONITOR_PATH.c_str(), IN_CREATE | IN_MODIFY);

    if(wd < 0)
    {
        cerr << "Failed to add watch on" << MONITOR_PATH << endl;
        return;
    }

    char buffer[BUFFER_SIZE];

    while (true)
    {
        int length = read(fd, buffer, BUFFER_SIZE);

        if(length < 0)
        {
            cerr << "Error reading inotify events" << endl;
            break;
        }

        int i = 0;

        while (i < length)
        {
            struct inotify_event *event = (struct inotify_event*) &buffer[i];

            if (event->len)
            {
                string filePath = MONITOR_PATH + "/" + event->name;

                if (event->mask & IN_CREATE)
                {
                    cout << "File create event detected: " << filePath << endl;
                    enqueueFile(filePath);
                }
                else if(event->mask & IN_MODIFY)
                {
                    cout << "File modify event detected: " << filePath << endl;
                    enqueueFile(filePath);
                }
                else if(event->mask & IN_DELETE)
                {
                    cout << "File was deleted: " << filePath << endl;
                }
            }

            i+= sizeof(struct inotify_event) + event->len;
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);
}

void startApiServer()
{
    httplib::Server svr;

    svr.Get("/status", [](const httplib::Request&, httplib::Response& res){
        res.set_content("DLP Endpoint Agent is running.", "text/plain");
    });

    // svr.Post("/scan", [](const httplib::Request& req, httplib::Response& res) {
    //     string filePath = req.body; //Assuming body contains the file path

    //     if(scanFileForSensitiveData(filePath))
    //     {
    //         res.set_content("Sensitive content detected.", "text/plain");
    //         logScanResult(filePath, true);
    //     }
    //     else
    //     {
    //         res.set_content("No sensitive content found.", "text/plain");
    //         logScanResult(filePath, false);
    //     }
    // });

    svr.Post("/enqueue", [](const httplib::Request &req, httplib::Response &res) {
        string filePath = req.body;
        enqueueFileApi(filePath);
        res.set_content("File enqueued for scanning", "text/plain");
    });

    svr.Get("/results", [](const httplib::Request &req, httplib::Response &res) {
        string filePath = req.get_param_value("file");
        bool result = getScanResults(filePath);
        res.set_content(result ? "Sensitive content detected." : "No sensitive content found.", "text/plain");
    });

    svr.Get("/logs", [](const httplib::Request &, httplib::Response &res) {
        ifstream logFile("scan_log.txt");
        if(!logFile.is_open())
        {
            res.set_content("Failed to open log file.", "text/plain");
            return;
        }

        ostringstream ss;
        ss << logFile.rdbuf();
        res.set_content(ss.str(), "text/plain");
    });

    svr.Post("/clear_logs", [](const httplib::Request &, httplib::Response &res) {
        ofstream logFile("scan_log.txt", ios::trunc);
        if(!logFile.is_open())
        {
            res.set_content("Failed to clear log file.", "text/plain");
            return;
        }
        res.set_content("Log file cleared.", "text/plain");
    });

    cout << "Starting API server on port 8080..." << endl;
    svr.listen("0.0.0.0", 8080);
}

int main()
{
    thread queueThread(processFileQueue);
    thread monitorThread(monitorFiles);

    startApiServer();

    monitorThread.join();
    queueThread.join();

    return 0;
}