/*
This file was created by 12345koip for the
LuGo Structure Dumper, a subproject of the
LuGo executor.

See LICENSE and README for details.
*/

#include <windows.h>
#include <thread>
#include <string>
#include <sstream>
#include <fstream>
#include "Dumpers/DumperBase.hpp"
#include "Dumpers/LuaState/LuaState.hpp"
#include "Dumpers/TValue/TValue.hpp"
#include "Dumpers/TString/TString.hpp"
#include "Dumpers/Udata/Udata.hpp"
#include "Dumpers/LuauBuffer/LuauBuffer.hpp"
#include "Dumpers/Closure/Closure.hpp"
#include "Dumpers/LuaTable/LuaTable.hpp"
#include "Dumpers/GlobalState/GlobalState.hpp"
#include "Misc/FileBits/FileBits.hpp"

using namespace LuDumper::Dumpers;

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



    //dumps -----
    LuaStateDumper luaStateDumper;
    luaStateDumper.Scan();

    TValueDumper tvalueDumper;
    tvalueDumper.Scan();

    TStringDumper tstringDumper;
    tstringDumper.Scan();

    UdataDumper udataDumper;
    udataDumper.Scan();

    LuauBufferDumper bufferDumper;
    bufferDumper.Scan();

    ClosureDumper clDumper;
    clDumper.Scan();

    LuaTableDumper tableDumper;
    tableDumper.Scan();

    GlobalStateDumper gsDumper;
    gsDumper.Scan();
    //-----------





    //Luau file buf.
    std::ostringstream lbuf;
    lbuf << COMMON_FILE_TOP << NEWLINE << NEWLINE <<
        INCLUDE_ONCE << NEWLINE << NEWLINE <<
        LUAU_DUMP_INCLUDES << NEWLINE << NEWLINE <<
        FORWARD_LUA_STATE << NEWLINE << FORWARD_LUA_TABLE <<
        NEWLINE << FORWARD_UPVAL << NEWLINE << FORWARD_TVALUE <<
        NEWLINE << FORWARD_GLOBAL_STATE << NEWLINE << FORWARD_GCOBJECT <<
        NEWLINE << FORWARD_VALUE << NEWLINE << FORWARD_LBUFFER << NEWLINE << FORWARD_PROTO << NEWLINE << NEWLINE << NEWLINE << BUFFER_TYPEDEF <<
        NEWLINE << FUNC_TYPEDEFS << NEWLINE << NEWLINE << REMOVE_STRUCT_PREF << NEWLINE << NEWLINE <<
        STKID_TYPEDEF << NEWLINE << NEWLINE << NEWLINE << NEWLINE;

    lbuf << LuDumper::FileBits::GetStaticLuauStructs() << NEWLINE;


    //add structs.
    lbuf << NEWLINE << NEWLINE;
    lbuf << luaStateDumper.ToHeaderContents();
    lbuf << NEWLINE << NEWLINE;
    lbuf << tvalueDumper.ToHeaderContents();
    lbuf << NEWLINE << NEWLINE;
    lbuf << tstringDumper.ToHeaderContents();
    lbuf << NEWLINE << NEWLINE;
    lbuf << udataDumper.ToHeaderContents();
    lbuf << NEWLINE << NEWLINE;
    lbuf << bufferDumper.ToHeaderContents();
    lbuf << NEWLINE << NEWLINE;
    lbuf << clDumper.ToHeaderContents();
    lbuf << NEWLINE << NEWLINE;

    std::ofstream file ("C:\\Users\\danba\\Downloads\\lfields.h");
    file << lbuf.str();
    file.close();

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