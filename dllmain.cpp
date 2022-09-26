#include <Windows.h>

// Made easy by KC#0005
// Simple unlocker for Call of Duty: Modern Warfare
// Credit to the Unknowncheats Post: https://www.unknowncheats.me/forum/call-of-duty-modern-warfare/505531-soft-unlock-method.html

uintptr_t baseAddress = (uintptr_t)GetModuleHandle(NULL);
uintptr_t unlockoffset = 0x0; 
// signature for the offset : 33 FF 48 8D 15 ? ? ? ? 48 89 05 ? ? ? ? 48 8D 0D 
// Can be found with Cheat Engine or IDA, replace 0x0 with the offset you find.
// If you're smart enough, you can just implement the pattern scan into the code so you wont need to update the offset every update

template <typename T>
static T readMemory(uintptr_t address)
{
    return *(T*)address;
}

template <typename T>
static void writeMemory(uintptr_t address, const T& value)
{
    *(T*)address = value;
}

void unlock()
{
    uintptr_t num = (unlockoffset + 0xC);
    int num2 = readMemory<int>(num);
    uintptr_t UnlockOffset = num + num2 + 4 - baseAddress;
    uintptr_t numP = (baseAddress + UnlockOffset + 0x60);
    memcpy((BYTE*)numP, (BYTE*)"\x48\x83\xC4\x08\x48\x8B\x5C\x24\x30\x48\x8B\x74\x24\x38\x48\x83\xC4\x20\x5F\x48\xC7\xC0\x01\x00\x00\x00\xC3", 28);
    writeMemory<uintptr_t>(baseAddress + UnlockOffset + 8, numP);
    writeMemory<uintptr_t>(baseAddress + UnlockOffset, baseAddress + UnlockOffset);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)unlock , nullptr, 0, nullptr); // CreateThread is a bad idea for detection reasons, IAT hooking is recomended.
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

