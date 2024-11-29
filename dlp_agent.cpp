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

#if defined(_WIN32) || defined(_WIN64)
    #define WINDOWS_PLATFORM
#elif defined(__linux__)
    #define LINUX_PLATFORM
#endif

//Config
const int BUFFER_SIZE = 1024 * (sizeof(struct inotify_event) + 16);
const string MONITOR_PATH = "./monitor";

queue<string> fileQueue;
mutex queueMutex;
condition_variable cv;
//bool terminate = false;

unordered_map<string, bool> scanResults;
mutex resultsMutex;

//Define secure token
const string API_TOKEN = "secure-token-123456";

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

void getScanResults(const string &filePath, httplib::Response &res)
{
    lock_guard<mutex> lock(resultsMutex);
    bool sensitiveDataFound;

    if(&filePath != nullptr)
    {
        if(scanResults.find(filePath) != scanResults.end())
        {
            sensitiveDataFound = scanResults[filePath];
            res.set_content(
                        "File: " + filePath + ", Sensitive Data Found: " +
                        (sensitiveDataFound ? "Yes" : "No"), "text/plain");
        }
        else
        {
            res.set_content("No results found for the specified file path.", "text/plain");
        }
    }
    else
    {
        if(scanResults.empty())
        {
            res.set_content("No results found.", "text/plain");
            return;
        }

        ostringstream oss;
        for(const auto &[filePath, sensitiveDataFound] : scanResults)
        {
            oss << "File: " << filePath << ", Sensitive Data Found: "
                << (sensitiveDataFound ? "Yes" : "No") << "\n";
        }
        res.set_content(oss.str(), "text/plain");
    }
    

    return;
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

void monitorFilesLinux()
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

#ifdef WINDOWS_PLATFORM
#include <windows.h>


void monitorFilesWindows(const string &directory)
{
    HANDLE hDir = CreateFile( directory.c_str(),
                            FILE_LIST_DIRECTORY,
                            FILE_SHARED_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            NULL,
                            OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS,
                            NULL);

    if (hDir == INVALID_HANDLE_VALUE)
    {
        cerr << "Error operating directory handle: " << GetLastError() << endl;
        return;        
    }

    const DWORD bufferSize = 1024 * 10;
    vector<BYTE> buffer(bufferSize);
    DWORD bytesReturned;

    while (true)
    {
        if (ReadDirectoryChangesW( hDir,
                                buffer.data(),
                                bufferSize,
                                TRUE, // Monitor subdirectories
                                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
                                &bytesReturned,
                                NULL,
                                NULL))
        {
            DWORD offset = 0;
            while (offset < bytesReturned) 
            {
                FILE_NOTIFY_INFORMATION *fni = (FILE_NOTIFY_INFORMATION *) &buffer[offset];
                wstring fileName(fni->FileName, fni->FileNameLength / sizeof(WCHAR));

                switch(fni->Action) {
                    
                    case FILE_ACTION_ADDED:
                        wcout << L"File created: " << fileName << endl;
                        break;
                    
                    case FILE_ACTION_MODIFIED:
                        wcout << L"File modfied: " << fileName << endl;
                        break;

                    case FILE_ACTION_REMOVED:
                        wcout << L"File deleted: " << fileName << endl;
                        break;

                    default:
                        break;
                }

                offset += fni->NextEntryOffset;

                if (fni->NextEntryOffset == 0)
                    break;
            }
        }
        else
        {
            cerr << "Error reading directory changes: " << GetLastError() << endl;
            break;
        }
    }

    CloseHandle(hDir);
}
#endif


//File monitoring function
void monitorFiles()
{

#ifdef LINUX_PLATFORM
    monitorFilesLinux();
#elif defined(WINDOWS_PLATFORM)
    monitorFilesWindows(MONITOR_PATH);
#endif
    
}

//Authentication funciton
bool authenticate(const httplib::Request &req)
{
    if(req.has_header("Authorization"))
    {
        auto token = req.get_header_value("Authorization");
        return token == "Bearer " + API_TOKEN;
    }

    return false;
}

void startApiServer()
{
    httplib::Server svr;

    svr.Get("/status", [](const httplib::Request &req, httplib::Response &res){
        if(!authenticate(req))
        {
            res.status = 401;
            res.set_content("Unauthorized","text/plain");
            return;
        }
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
        if(!authenticate(req))
        {
            res.status = 401;
            res.set_content("Unauthorized","text/plain");
            return;
        }

        if(req.has_param("file"))
        {
            string filePath = req.get_param_value("file");
            getScanResults(filePath, res);
            //res.set_content(result ? "Sensitive content detected." : "No sensitive content found.", "text/plain");
        }
        else
        {
            getScanResults(NULL, res);
        }
        return;
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