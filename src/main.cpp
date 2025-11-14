#include <coreinit/thread.h>
#include <sys/stat.h>
#include <stdio.h>
#include <time.h>
#include <coreinit/debug.h>
#include <whb/log.h>
#include <whb/log_console.h>
#include <whb/proc.h>
#include <string.h>
#include <nn/ac.h>
#include <nn/act.h>
#include <nsysnet/nssl.h>

#include <stdbool.h>
#include <stdio.h>

typedef unsigned int u8;
typedef unsigned int u32;
typedef unsigned int u64;
typedef unsigned int s32;

struct nnolvInitializeParam
{
    u32 flags;
    u32 reportTypes;
    u8 *work;
    u32 workSize;
    const void *args;
    u32 argsSize;
    u8 reserved[40];
};

extern "C" void nnolvInitializeParam_ctor(nnolvInitializeParam *thisPtr) asm("__ct__Q3_2nn3olv15InitializeParamFv");

extern "C" u32 nnolvInitializeParam_SetFlags(nnolvInitializeParam *thisPtr, u32 flags) asm("SetFlags__Q3_2nn3olv15InitializeParamFUi");

extern "C" u32 nnolvInitializeParam_SetWork(nnolvInitializeParam *thisPtr, u8 *work, u32 size) asm("SetWork__Q3_2nn3olv15InitializeParamFPUcUi");

extern "C" u32 nnolvInitializeParam_SetSysArgs(nnolvInitializeParam *thisPtr, const void *args, u32 size) asm("SetSysArgs__Q3_2nn3olv15InitializeParamFPCvUi");

extern "C" u32 nnolvInitializeParam_SetReportTypes(nnolvInitializeParam *thisPtr, u32 flags) asm("SetReportTypes__Q3_2nn3olv15InitializeParamFUi");

extern "C" u32 nnolvInitialize(const nnolvInitializeParam *param) asm("Initialize__Q2_2nn3olvFPCQ3_2nn3olv15InitializeParam");

extern "C" u32 nnolvFinalize(void) asm("Finalize__Q2_2nn3olvFv");

extern "C" uint32_t nnolvGetServiceToken(char *buf, unsigned int bufSize) asm("GetServiceToken__Q2_2nn3olvFPcUi");

extern "C" uint32_t nnolvGetParamPack(char *buf, unsigned int bufSize) asm("GetParamPack__Q2_2nn3olvFPcUi");

void InitializeMiiverse()
{
    alignas(8) nnolvInitializeParam paramStorage;
    nnolvInitializeParam *param = &paramStorage;

    nnolvInitializeParam_ctor(param);

    static u8 workBuffer[256 * 1024];

    nnolvInitializeParam_SetFlags(param, 0);
    nnolvInitializeParam_SetWork(param, workBuffer, sizeof(workBuffer));

    u32 rc = nnolvInitialize(param);

    // Discovery request success
    if (rc != 0x01100080)
    {
        WHBLogPrintf("[nn::olv] nn::olv::Initialize failed (rc=%08X)\n", rc);
    }
    else
    {
        WHBLogPrintf("[nn::olv] nn::olv::Initialize SUCCESS! -> (rc=%08X)\n", rc);

        char tokenBuf[513] = {};
        u32 rcTok = nnolvGetServiceToken(tokenBuf, sizeof(tokenBuf));

        if (rcTok != 0x01100080)
        {
            WHBLogPrintf("[nn::olv] nn::olv::GetServiceToken failed (rc=%08X)\n", rcTok);
        }
        else
        {
            WHBLogPrintf("[nn::olv] nn::olv::GetServiceToken SUCCESS! -> (rc=%08X)\n", rcTok);
            WHBLogPrintf("[nn::olv] Service Token: %s\n", tokenBuf);
        }

        char packBuf[513] = {};
        u32 rcPack = nnolvGetParamPack(packBuf, sizeof(packBuf));

        if (rcPack != 0x01100080)
        {
            WHBLogPrintf("[nn::olv] nn::olv::GetParamPack failed (rc=%08X)\n", rcPack);
        }
        else
        {
            WHBLogPrintf("[nn::olv] nn::olv::GetParamPack SUCCESS! -> (rc=%08X)\n", rcPack);
            WHBLogPrintf("[nn::olv] Param Pack: %s\n", packBuf);
        }

        WHBLogPrintf("Saving Miiverse auth data to SD Card...\n");

        // Get current user's PID
        nn::act::PrincipalId pid = nn::act::GetPrincipalId();

        // Get current user's NNID
        char accid[17] = {};
        nn::act::GetAccountId(accid);

        // Create folder if it doesn't exist
        const char *folderPath = "fs:/vol/external01/miiverse_auth";
        mkdir(folderPath, 0777); // create folder if missing

        // Get current timestamp
        time_t now = time(NULL);
        struct tm t;
        localtime_r(&now, &t); // fills struct tm with local time

        char filePath[512];
        snprintf(filePath, sizeof(filePath),
                 "%s/token_%s_%04d%02d%02d%02d%02d%02d.txt",
                 folderPath,
                 accid,
                 t.tm_year + 1900,
                 t.tm_mon + 1,
                 t.tm_mday,
                 t.tm_hour,
                 t.tm_min,
                 t.tm_sec);

        // Write to file
        FILE *fp = fopen(filePath, "w");
        if (fp)
        {
            fprintf(fp, "Service Token: %s\n", tokenBuf);
            fprintf(fp, "Param Pack: %s\n", packBuf);
            fprintf(fp, "User ID: %s\n", accid);
            fprintf(fp, "Principal ID: %u\n", pid);
            fclose(fp);

            WHBLogPrintf("Successfully saved Miiverse auth data to SD Card:\n");
            WHBLogPrintf("%s\n", filePath);
        }
        else
        {
            WHBLogPrintf("Failed to write SD Card file:\n");
            WHBLogPrintf("%s\n", filePath);
        }
    }
}

int main(int argc, char **argv)
{
    WHBProcInit();
    WHBLogConsoleInit();

    WHBLogPrintf("Initializing network...\n");
    WHBLogConsoleDraw();
    OSSleepTicks(OSMillisecondsToTicks(10));

    nn::ac::Initialize();
    nn::ac::ConfigIdNum configId;
    nn::ac::GetStartupId(&configId);
    nn::ac::Connect(configId);

    WHBLogPrintf("Initializing NSSL...\n");
    WHBLogConsoleDraw();
    OSSleepTicks(OSMillisecondsToTicks(10));

    // Without NSSL being initialized first, nn::olv itself is never initialized?
    NSSLInit();

    WHBLogPrintf("Initializing account...\n");
    WHBLogConsoleDraw();
    OSSleepTicks(OSMillisecondsToTicks(10));

    nn::act::Initialize();

    WHBLogPrintf("[nn::olv] Starting Miiverse initialization...\n");
    WHBLogConsoleDraw();

    InitializeMiiverse();

    while (WHBProcIsRunning())
    {
        WHBLogConsoleDraw();
        OSSleepTicks(OSMillisecondsToTicks(25));
    }

    // After error report/After success
    nnolvFinalize();
    NSSLFinish();
    nn::act::Finalize();
    nn::ac::Finalize();

    return 0;
}
