/*
This file was created by 12345koip for the
LuGo Structure Dumper, a subproject of the
LuGo executor.

See LICENSE and README for details.
*/

#include <windows.h>
#include <thread>

static void InitConsole() {
    BOOL r = AllocConsole();
    if (!r) exit(1);

    //std streams -> allocated console.
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);
    freopen_s(&fp, "CONIN$", "r", stdin);

    //title.
    SetConsoleTitleA("LuGo Structure Dumper");
}

void Entry() {
    InitConsole();

    //temporary keepalive.
    while (true)
        std::this_thread::sleep_for(std::chrono::seconds(1));
}

DWORD WINAPI EntryThread(LPVOID) {
    Entry();
    return 0;
}


BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReasonForCall, LPVOID reserved) {
    switch (dwReasonForCall) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)EntryThread, nullptr, 0, nullptr);
            break;
    }

    return TRUE;
}