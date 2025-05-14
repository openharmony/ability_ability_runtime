/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cj_environment.h"

#include <string>
#include <sstream>
#include <mutex>
#include "cj_hilog.h"
#include "cj_invoker.h"
#ifdef __OHOS__
#include <dlfcn.h>
#endif
#include "dynamic_loader.h"
#ifdef WITH_EVENT_HANDLER
#include "event_handler.h"
#endif

#ifdef APP_USE_ARM64
#define APP_LIB_NAME "arm64"
#elif defined(APP_USE_ARM)
#define APP_LIB_NAME "arm"
#elif defined(APP_USE_X86_64)
#define APP_LIB_NAME "x86_64"
#elif defined(NAPI_TARGET_ARM64)
#define APP_LIB_NAME "arm64"
#else
#error unsupported platform
#endif

namespace {
const std::string SANDBOX_LIB_PATH = "/data/storage/el1/bundle/libs/" APP_LIB_NAME;
const std::string CJ_RT_PATH = SANDBOX_LIB_PATH + "/runtime";
const std::string CJ_LIB_PATH = SANDBOX_LIB_PATH + "/ohos";
const std::string CJ_SYSLIB_PATH = "/system/lib64:/system/lib64/platformsdk";
const std::string CJ_CHIPSDK_PATH = "/system/lib64/chipset-pub-sdk";
const std::string CJ_SDK_PATH = "/system/lib64/platformsdk/cjsdk";
} // namespace

namespace OHOS {
namespace {
const char DEBUGGER_LIBNAME[] = "libcj_debugger.z.so";
const char DEBUGGER_SYMBOL_NAME[] = "StartDebuggerServer";
const char INIT_CJRUNTIME_SYMBOL_NAME[] = "InitCJRuntime";
const char INIT_UISCHEDULER_SYMBOL_NAME[] = "InitUIScheduler";
const char RUN_UISCHEDULER_SYMBOL_NAME[] = "RunUIScheduler";
const char FINI_CJRUNTIME_SYMBOL_NAME[] = "FiniCJRuntime";
const char INIT_CJLIBRARY_SYMBOL_NAME[] = "InitCJLibrary";
const char REGISTER_EVENTHANDLER_CALLBACKS_NAME[] = "RegisterEventHandlerCallbacks";
const char REGISTER_ARKVM_SYMBOL_NAME[] = "RegisterArkVMInRuntime";
const char REGISTER_STACKINFO_CALLBACKS_NAME[] = "RegisterStackInfoCallbacks";
const char DUMP_HEAP_SNAPSHOT_NAME[] = "CJ_MRT_DumpHeapSnapshot";
const char FORCE_FULL_GC_NAME[] = "CJ_MRT_ForceFullGC";

using InitCJRuntimeType = int(*)(const struct RuntimeParam*);;
using InitUISchedulerType = void*(*)();
using RunUISchedulerType = int(*)(unsigned long long);
using FiniCJRuntimeType = int(*)();
using InitCJLibraryType = int(*)(const char*);
using RegisterEventHandlerType = void(*)(PostTaskType, HasHigherPriorityType);
using RegisterArkVMType = void(*)(unsigned long long);
using RegisterStackInfoType = void(*)(UpdateStackInfoFuncType);
using DumpHeapSnapshotType = void(*)(int);
using ForceFullGCType = void(*)();

#ifdef __OHOS__
const char REGISTER_UNCAUGHT_EXCEPTION_NAME[] = "RegisterUncaughtExceptionHandler";
using RegisterUncaughtExceptionType = void (*)(const CJUncaughtExceptionInfo& handle);
#endif

#ifdef WITH_EVENT_HANDLER
static std::shared_ptr<AppExecFwk::EventHandler> g_handler = nullptr;
#endif

bool LoadSymbolInitCJRuntime(void* handle, CJRuntimeAPI& apis)
{
    auto symbol = DynamicFindSymbol(handle, INIT_CJRUNTIME_SYMBOL_NAME);
    if (symbol == nullptr) {
        LOGE("runtime api not found: %{public}s", INIT_CJRUNTIME_SYMBOL_NAME);
        return false;
    }
    apis.InitCJRuntime = reinterpret_cast<InitCJRuntimeType>(symbol);
    return true;
}

bool LoadSymbolInitUIScheduler(void* handle, CJRuntimeAPI& apis)
{
    auto symbol = DynamicFindSymbol(handle, INIT_UISCHEDULER_SYMBOL_NAME);
    if (symbol == nullptr) {
        LOGE("runtime api not found: %{public}s", INIT_UISCHEDULER_SYMBOL_NAME);
        return false;
    }
    apis.InitUIScheduler = reinterpret_cast<InitUISchedulerType>(symbol);
    return true;
}

bool LoadSymbolRunUIScheduler(void* handle, CJRuntimeAPI& apis)
{
    auto symbol = DynamicFindSymbol(handle, RUN_UISCHEDULER_SYMBOL_NAME);
    if (symbol == nullptr) {
        LOGE("runtime api not found: %{public}s", RUN_UISCHEDULER_SYMBOL_NAME);
        return false;
    }
    apis.RunUIScheduler = reinterpret_cast<RunUISchedulerType>(symbol);
    return true;
}

bool LoadSymbolFiniCJRuntime(void* handle, CJRuntimeAPI& apis)
{
    auto symbol = DynamicFindSymbol(handle, FINI_CJRUNTIME_SYMBOL_NAME);
    if (symbol == nullptr) {
        LOGE("runtime api not found: %{public}s", FINI_CJRUNTIME_SYMBOL_NAME);
        return false;
    }
    apis.FiniCJRuntime = reinterpret_cast<FiniCJRuntimeType>(symbol);
    return true;
}

bool LoadSymbolInitCJLibrary(void* handle, CJRuntimeAPI& apis)
{
    auto symbol = DynamicFindSymbol(handle, INIT_CJLIBRARY_SYMBOL_NAME);
    if (symbol == nullptr) {
        LOGE("runtime api not found: %{public}s", INIT_CJLIBRARY_SYMBOL_NAME);
        return false;
    }
    apis.InitCJLibrary = reinterpret_cast<InitCJLibraryType>(symbol);
    return true;
}

bool LoadSymbolRegisterEventHandlerCallbacks(void* handle, CJRuntimeAPI& apis)
{
    auto symbol = DynamicFindSymbol(handle, REGISTER_EVENTHANDLER_CALLBACKS_NAME);
    if (symbol == nullptr) {
        LOGE("runtime api not found: %{public}s", REGISTER_EVENTHANDLER_CALLBACKS_NAME);
        return false;
    }
    apis.RegisterEventHandlerCallbacks = reinterpret_cast<RegisterEventHandlerType>(symbol);
    return true;
}

bool LoadSymbolRegisterStackInfoCallbacks(void* handle, CJRuntimeAPI& apis)
{
    auto symbol = DynamicFindSymbol(handle, REGISTER_STACKINFO_CALLBACKS_NAME);
    if (symbol == nullptr) {
        LOGE("runtime api not found: %{public}s", REGISTER_STACKINFO_CALLBACKS_NAME);
        // return true for compatible.
        apis.RegisterStackInfoCallbacks = nullptr;
        return true;
    }
    apis.RegisterStackInfoCallbacks = reinterpret_cast<RegisterStackInfoType>(symbol);
    return true;
}

bool LoadSymbolRegisterArkVM(void* handle, CJRuntimeAPI& apis)
{
    auto symbol = DynamicFindSymbol(handle, REGISTER_ARKVM_SYMBOL_NAME);
    if (symbol == nullptr) {
        LOGE("runtime api not found: %{public}s", REGISTER_ARKVM_SYMBOL_NAME);
        // return true for compatible.
        apis.RegisterArkVMInRuntime = nullptr;
        return true;
    }
    apis.RegisterArkVMInRuntime = reinterpret_cast<RegisterArkVMType>(symbol);
    return true;
}

#ifdef __OHOS__
bool LoadSymbolRegisterCJUncaughtExceptionHandler(void* handle, CJRuntimeAPI& apis)
{
    auto symbol = DynamicFindSymbol(handle, REGISTER_UNCAUGHT_EXCEPTION_NAME);
    if (symbol == nullptr) {
        LOGE("runtime api not found: %{public}s", REGISTER_UNCAUGHT_EXCEPTION_NAME);
        return false;
    }
    apis.RegisterCJUncaughtExceptionHandler = reinterpret_cast<RegisterUncaughtExceptionType>(symbol);
    return true;
}
#endif

bool LoadSymbolDumpHeapSnapshot(void* handle, CJRuntimeAPI& apis)
{
    auto symbol = DynamicFindSymbol(handle, DUMP_HEAP_SNAPSHOT_NAME);
    if (symbol == nullptr) {
        LOGE("runtime api not found: %{public}s", DUMP_HEAP_SNAPSHOT_NAME);
        // return true for compatible.
        apis.DumpHeapSnapshot = nullptr;
        return true;
    }
    apis.DumpHeapSnapshot = reinterpret_cast<DumpHeapSnapshotType>(symbol);
    return true;
}

bool LoadSymbolForceFullGC(void* handle, CJRuntimeAPI& apis)
{
    auto symbol = DynamicFindSymbol(handle, FORCE_FULL_GC_NAME);
    if (symbol == nullptr) {
        LOGE("runtime api not found: %{public}s", FORCE_FULL_GC_NAME);
        // return true for compatible.
        apis.ForceFullGC = nullptr;
        return true;
    }
    apis.ForceFullGC = reinterpret_cast<ForceFullGCType>(symbol);
    return true;
}

bool PostTaskWrapper(void* func)
{
    return CJEnvironment::GetInstance()->PostTask(reinterpret_cast<TaskFuncType>(func));
}

bool HasHigherPriorityTaskWrapper()
{
    return CJEnvironment::GetInstance()->HasHigherPriorityTask();
}

CJEnvironment* instance_ = nullptr;
} // namespace

const char *CJEnvironment::cjAppNSName = "cj_app";
const char *CJEnvironment::cjSDKNSName = "cj_app_sdk";
const char *CJEnvironment::cjSysNSName = "cj_system";
const char *CJEnvironment::cjChipSDKNSName = "cj_chipsdk";
const char *CJEnvironment::cjNewAppNSName = "moduleNs_default";
const char *CJEnvironment::cjNewSDKNSName = "cj_rom_sdk";
const char *CJEnvironment::cjNewSysNSName = "default";
const char *CJEnvironment::cjNDKNSName = "ndk";
const char *CJEnvironment::cjCompatibilitySDKNSName = "cj_compatibility_sdk";
std::string CJEnvironment::appVersion = "5.1.0.0";
const uint32_t CJEnvironment::majorVersion = 5;
const uint32_t CJEnvironment::minorVersion = 1;

#ifdef WITH_EVENT_HANDLER
static std::shared_ptr<AppExecFwk::EventHandler>GetGHandler()
{
    if (g_handler == nullptr) {
        g_handler = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    }
    return g_handler;
}
#endif

void CJEnvironment::InitSpawnEnv()
{
#ifdef WITH_EVENT_HANDLER
    GetGHandler();
#endif
    instance_ = new CJEnvironment(NSMode::SINK);
    instance_->PreloadLibs();
}

void CJEnvironment::PreloadLibs()
{
    LOGI("start Preloadlibs");
    auto lib = LoadCJLibrary(SDK, "libohos.ability.so");
    if (lib) {
        preloadLibs_.emplace_back(lib);
    }
    lib = LoadCJLibrary(SDK, "libohos.component.so");
    if (lib) {
        preloadLibs_.emplace_back(lib);
    }
    lib = LoadCJLibrary(SDK, "libohos.window.so");
    if (lib) {
        preloadLibs_.emplace_back(lib);
    }
}

void CJEnvironment::SetAppPath(const std::string& appPath)
{
    static bool isInited = false;
    static std::mutex initMutex;
    std::lock_guard<std::mutex> lock(initMutex);
    if (isInited) {
        return;
    }
    auto mode = DetectAppNSMode();
    if (instance_) {
        if (instance_->nsMode_ == mode) {
            instance_->InitCJNS(appPath);
            return;
        }
        delete instance_;
    }
    instance_ = new CJEnvironment(mode);
    instance_->InitCJNS(appPath);
    isInited = true;
}

CJEnvironment::CJEnvironment(NSMode mode) : nsMode_(mode)
{
    InitRuntimeNS();
    LoadRuntimeApis();
}

CJEnvironment::~CJEnvironment()
{
    StopRuntime();

    delete lazyApis_;

    for (auto lib : preloadLibs_) {
        dlclose(lib);
    }
}

CJEnvironment* CJEnvironment::GetInstance()
{
    return instance_;
}

bool CJEnvironment::RegisterCangjieCallback()
{
    constexpr char CANGJIE_DEBUGGER_LIB_PATH[] = "libark_connect_inspector.z.so";
    auto handlerConnectServerSo = LoadCJLibrary(CJEnvironment::SYSTEM, CANGJIE_DEBUGGER_LIB_PATH);
    if (handlerConnectServerSo == nullptr) {
        LOGE("null handlerConnectServerSo: %{public}s", dlerror());
        return false;
    }
    using SendMsgCB = const std::function<void(const std::string& message)>;
    using SetCangjieCallback = void(*)(const std::function<void(const std::string& message, SendMsgCB)>);
    using CangjieCallback = void(*)(const std::string& message, SendMsgCB);
    auto setCangjieCallback = reinterpret_cast<SetCangjieCallback>(
        DynamicFindSymbol(handlerConnectServerSo, "SetCangjieCallback"));
    if (setCangjieCallback == nullptr) {
        LOGE("null setCangjieCallback: %{public}s", dlerror());
        return false;
    }
    #define RTLIB_NAME "libcangjie-runtime.so"
    auto dso = LoadCJLibrary(CJEnvironment::SDK, RTLIB_NAME);
    if (!dso) {
        LOGE("load library failed: %{public}s", RTLIB_NAME);
        return false;
    }
    LOGE("load libcangjie-runtime.so success");
    #define PROFILERAGENT "ProfilerAgent"
    CangjieCallback cangjieCallback = reinterpret_cast<CangjieCallback>(DynamicFindSymbol(dso, PROFILERAGENT));
    if (cangjieCallback == nullptr) {
        dlclose(handlerConnectServerSo);
        handlerConnectServerSo = nullptr;
        LOGE("runtime api not found: %{public}s", PROFILERAGENT);
        return false;
    }
    LOGE("find runtime api success");
    setCangjieCallback(cangjieCallback);
    dlclose(handlerConnectServerSo);
    handlerConnectServerSo = nullptr;
    return true;
}

bool CJEnvironment::LoadRuntimeApis()
{
    if (isRuntimeApiLoaded) {
        return true;
    }
    lazyApis_ = new CJRuntimeAPI();
#ifdef __WINDOWS__
#define RTLIB_NAME "libcangjie-runtime.dll"
#else
#define RTLIB_NAME "libcangjie-runtime.so"
#endif
#ifdef __OHOS__
    Dl_namespace ns;
    dlns_get(nsMode_ == NSMode::APP ? cjSDKNSName : cjNewSDKNSName, &ns);
    std::string runtimeLibName = "libcangjie-runtime";
    runtimeLibName += ".so";
    auto dso = DynamicLoadLibrary(&ns, runtimeLibName.c_str(), 1);
#else
    auto dso = DynamicLoadLibrary(RTLIB_NAME, 1);
#endif
    if (!dso) {
        LOGE("load library failed: %{public}s", RTLIB_NAME);
        return false;
    }
#undef RTLIB_NAME
    preloadLibs_.emplace_back(dso);
    if (!LoadSymbolInitCJRuntime(dso, *lazyApis_) ||
        !LoadSymbolInitUIScheduler(dso, *lazyApis_) ||
        !LoadSymbolRunUIScheduler(dso, *lazyApis_) ||
        !LoadSymbolFiniCJRuntime(dso, *lazyApis_) ||
        !LoadSymbolInitCJLibrary(dso, *lazyApis_) ||
        !LoadSymbolRegisterEventHandlerCallbacks(dso, *lazyApis_) ||
        !LoadSymbolRegisterStackInfoCallbacks(dso, *lazyApis_) ||
        !LoadSymbolRegisterArkVM(dso, *lazyApis_) ||
        !LoadSymbolDumpHeapSnapshot(dso, *lazyApis_) ||
        !LoadSymbolForceFullGC(dso, *lazyApis_)) {
        LOGE("load symbol failed");
        DynamicFreeLibrary(dso);
        return false;
    }
#ifdef __OHOS__
    if (!LoadSymbolRegisterCJUncaughtExceptionHandler(dso, *lazyApis_)) {
        LOGE("load symbol RegisterCJUncaughtExceptionHandler failed");
        DynamicFreeLibrary(dso);
        return false;
    }
#endif
    isRuntimeApiLoaded = true;
    return true;
}

void CJEnvironment::RegisterArkVMInRuntime(unsigned long long externalVM)
{
    if (lazyApis_ == nullptr) {
        return;
    }
    if (lazyApis_->RegisterArkVMInRuntime == nullptr) {
        return;
    }
    lazyApis_->RegisterArkVMInRuntime(externalVM);
}

void CJEnvironment::RegisterStackInfoCallbacks(UpdateStackInfoFuncType uFunc)
{
    if (lazyApis_ == nullptr) {
        return;
    }
    if (lazyApis_->RegisterStackInfoCallbacks == nullptr) {
        return;
    }
    lazyApis_->RegisterStackInfoCallbacks(uFunc);
}

void CJEnvironment::RegisterCJUncaughtExceptionHandler(const CJUncaughtExceptionInfo& handle)
{
    if (lazyApis_ == nullptr) {
        return;
    }
    if (lazyApis_->RegisterCJUncaughtExceptionHandler == nullptr) {
        return;
    }
    lazyApis_->RegisterCJUncaughtExceptionHandler(handle);
}

void CJEnvironment::DumpHeapSnapshot(int fd)
{
    if (lazyApis_ == nullptr) {
        return;
    }
    if (lazyApis_->DumpHeapSnapshot == nullptr) {
        return;
    }
    lazyApis_->DumpHeapSnapshot(fd);
}

void CJEnvironment::ForceFullGC()
{
    if (lazyApis_ == nullptr) {
        return;
    }
    if (lazyApis_->ForceFullGC == nullptr) {
        return;
    }
    lazyApis_->ForceFullGC();
}

bool CJEnvironment::PostTask(TaskFuncType task)
{
#ifdef WITH_EVENT_HANDLER
    if (task == nullptr) {
        LOGE("null task could not be posted");
        return false;
    }

    bool postDone = GetGHandler()->PostTask(task, "spawn-main-task-from-cj", 0, AppExecFwk::EventQueue::Priority::HIGH);
    if (!postDone) {
        LOGE("event handler support cj ui scheduler");
        return false;
    }
    return true;
#endif
    return true;
}

bool CJEnvironment::HasHigherPriorityTask()
{
#ifdef WITH_EVENT_HANDLER
    return GetGHandler()->HasPreferEvent(static_cast<int>(AppExecFwk::EventQueue::Priority::HIGH));
#endif
    return false;
}

void CJEnvironment::InitCJChipSDKNS(const std::string& path)
{
#ifdef __OHOS__
    LOGI("InitCJChipSDKNS: %{public}s", path.c_str());
    Dl_namespace chip_sdk;
    DynamicInitNamespace(&chip_sdk, nullptr, path.c_str(), CJEnvironment::cjChipSDKNSName);

    Dl_namespace cjnative;
    Dl_namespace current;
    dlns_get(nullptr, &current);
    dlns_get(CJEnvironment::cjNDKNSName, &cjnative);
    dlns_inherit(&chip_sdk, &cjnative, "allow_all_shared_libs");
    dlns_inherit(&chip_sdk, &current, "allow_all_shared_libs");
#endif
}

void CJEnvironment::InitNewCJChipSDKNS(const std::string& path)
{
#ifdef __OHOS__
    LOGI("InitCJChipSDKNS: %{public}s", path.c_str());
    Dl_namespace chip_sdk;
    DynamicInitNewNamespace(&chip_sdk, path.c_str(), CJEnvironment::cjChipSDKNSName);
#endif
}

// Init app namespace
void CJEnvironment::InitCJAppNS(const std::string& path)
{
#ifdef __OHOS__
    LOGI("InitCJAppNS: %{public}s", path.c_str());
    Dl_namespace cjnative;
    Dl_namespace sdk;
    Dl_namespace ns;
    Dl_namespace current;
    DynamicInitNamespace(&ns, nullptr, path.c_str(), CJEnvironment::cjAppNSName);
    dlns_get(CJEnvironment::cjNDKNSName, &cjnative);
    dlns_get(nullptr, &current);
    dlns_get(cjSDKNSName, &sdk);
    dlns_inherit(&ns, &cjnative, "allow_all_shared_libs");
    dlns_inherit(&cjnative, &current, "allow_all_shared_libs");
    dlns_inherit(&current, &cjnative, "allow_all_shared_libs");
    dlns_inherit(&ns, &sdk, "allow_all_shared_libs");
#endif
}

void CJEnvironment::InitNewCJAppNS(const std::string& path)
{
#ifdef __OHOS__
    LOGI("InitCJAppNS: %{public}s", path.c_str());
    Dl_namespace ns;
    DynamicInitNewNamespace(&ns, path.c_str(), CJEnvironment::cjNewAppNSName);
    Dl_namespace sdk;
    if (nsMode_ == NSMode::APP) {
        Dl_namespace chip_sdk;
        dlns_get(CJEnvironment::cjSDKNSName, &sdk);
        dlns_get(CJEnvironment::cjChipSDKNSName, &chip_sdk);
        dlns_inherit(&ns, &sdk, "allow_all_shared_libs");
        dlns_inherit(&ns, &chip_sdk, "libssl_openssl.z.so");
    } else {
        Dl_namespace compatibility_sdk;
        dlns_get(CJEnvironment::cjCompatibilitySDKNSName, &compatibility_sdk);
        dlns_get(CJEnvironment::cjNewSDKNSName, &sdk);
        dlns_inherit(&ns, &sdk, "allow_all_shared_libs");
        dlns_inherit(&ns, &compatibility_sdk, "allow_all_shared_libs");
    }
#endif
}

// Init cj sdk namespace
void CJEnvironment::InitCJSDKNS(const std::string& path)
{
#ifdef __OHOS__
    LOGI("InitCJSDKNS: %{public}s", path.c_str());
    Dl_namespace ns;
    DynamicInitNewNamespace(&ns, path.c_str(), cjSDKNSName);
#endif
}

void CJEnvironment::InitNewCJSDKNS(const std::string& path)
{
#ifdef __OHOS__
    LOGI("InitCJSDKNS: %{public}s", path.c_str());
    Dl_namespace ns;
    DynamicInitNewNamespace(&ns, path.c_str(), cjNewSDKNSName);
#endif
}

void CJEnvironment::InitCJCompatibilitySDKNS(const std::string& path)
{
#ifdef __OHOS__
    LOGI("InitCJCompatibilitySDKNS: %{public}s", path.c_str());
    Dl_namespace ns;
    DynamicInitNewNamespace(&ns, path.c_str(), cjCompatibilitySDKNSName);
#endif
}

// Init cj system namespace
void CJEnvironment::InitCJSysNS(const std::string& path)
{
#ifdef __OHOS__
    LOGI("InitCJSysNS: %{public}s", path.c_str());
    Dl_namespace cj_sdk;
    Dl_namespace cjnative;
    Dl_namespace ns;
    dlns_get(cjSDKNSName, &cj_sdk);
    DynamicInitNamespace(&ns, &cj_sdk, path.c_str(), cjSysNSName);
    dlns_get(CJEnvironment::cjNDKNSName, &cjnative);
    dlns_inherit(&ns, &cjnative, "allow_all_shared_libs");
#endif
}

bool CJEnvironment::StartRuntime()
{
    if (isRuntimeStarted_) {
        return true;
    }

    if (!LoadRuntimeApis()) {
        LOGE("LoadRuntimeApis failed");
        return false;
    }

    RuntimeParam rtParams {
        .heapParam = {
            .regionSize = 64,
            .heapSize = 256 * 1024,
            .exemptionThreshold= 0.8,
            .heapUtilization = 0.8,
            .heapGrowth = 0.15,
            .allocationRate = 0,
            .allocationWaitTime = 0,
        },
        .gcParam = {
            .gcThreshold = 0,
            .garbageThreshold = 0,
            .gcInterval = 0,
            .backupGCInterval = 0,
            .gcThreads = 0,
        },
        .logParam = {
            .logLevel = RTLOG_ERROR,
        },
        .coParam = {
            .thStackSize = 2 * 1024,
            .coStackSize = 2 * 1024,
            .processorNum = 8,
        }
    };

    auto status = lazyApis_->InitCJRuntime(&rtParams);
    if (status != E_OK) {
        LOGE("init cj runtime failed: %{public}d", status);
        return false;
    }

    lazyApis_->RegisterEventHandlerCallbacks(PostTaskWrapper, HasHigherPriorityTaskWrapper);

    isRuntimeStarted_ = true;
    return true;
}

void CJEnvironment::StopRuntime()
{
    if (!isRuntimeStarted_) {
        return;
    }

    if (isUISchedulerStarted_) {
        StopUIScheduler();
    }

    auto code = lazyApis_->FiniCJRuntime();
    if (code == E_OK) {
        isRuntimeStarted_ = false;
    }
}

bool CJEnvironment::StartUIScheduler()
{
    if (isUISchedulerStarted_) {
        return true;
    }

    uiScheduler_ = lazyApis_->InitUIScheduler();
    if (!uiScheduler_) {
        LOGE("init cj ui scheduler failed");
        return false;
    }

    isUISchedulerStarted_ = true;
    return true;
}

void CJEnvironment::StopUIScheduler()
{
    isUISchedulerStarted_ = false;
}

void* CJEnvironment::LoadCJLibrary(const char* dlName)
{
    if (!StartRuntime()) {
        LOGE("StartRuntime failed");
        return nullptr;
    }
    auto handle = LoadCJLibrary(APP, dlName);
    if (!handle) {
        LOGE("load cj library failed: %{public}s", DynamicGetError());
        return nullptr;
    }

    LOGI("LoadCJLibrary InitCJLibrary: %{public}s", dlName);
    auto status = lazyApis_->InitCJLibrary(dlName);
    if (status != E_OK) {
        LOGE("InitCJLibrary failed: %{public}s", dlName);
        UnLoadCJLibrary(handle);
        return nullptr;
    }
    CJEnvironment::RegisterCangjieCallback();
    isLoadCJLibrary_ = true;
    return handle;
}

void* CJEnvironment::LoadCJLibrary(OHOS::CJEnvironment::LibraryKind kind, const char* dlName)
{
#ifdef __OHOS__
    Dl_namespace ns;
    switch (kind) {
        case APP:
            dlns_get(CJEnvironment::cjNewAppNSName, &ns);
            break;
        case SYSTEM:
            dlns_get(CJEnvironment::cjNewSysNSName, &ns);
            break;
        case SDK:
            dlns_get(nsMode_ == NSMode::APP ? CJEnvironment::cjSDKNSName : CJEnvironment::cjNewSDKNSName, &ns);
            break;
    }
    auto handle = DynamicLoadLibrary(&ns, dlName, 0);
#else
    auto handle = DynamicLoadLibrary(dlName, 1);
#endif
    if (!handle) {
        LOGE("load cj library failed: %{public}s", DynamicGetError());
        return nullptr;
    }
    isLoadCJLibrary_ = true;
    return handle;
}

bool CJEnvironment::CheckLoadCJLibrary()
{
    return isLoadCJLibrary_;
}

void CJEnvironment::UnLoadCJLibrary(void* handle)
{
    DynamicFreeLibrary(handle);
}

void* CJEnvironment::GetSymbol(void* dso, const char* symbol)
{
    return DynamicFindSymbol(dso, symbol);
}

bool CJEnvironment::StartDebugger()
{
#ifdef __OHOS__
    Dl_namespace ns;
    dlns_get(CJEnvironment::cjNewSysNSName, &ns);
    auto handle = DynamicLoadLibrary(&ns, DEBUGGER_LIBNAME, 0);
#else
    auto handle = DynamicLoadLibrary(DEBUGGER_LIBNAME, 0);
#endif
    if (!handle) {
        LOGE("failed to load library: %{public}s", DEBUGGER_LIBNAME);
        return false;
    }
    auto symbol = DynamicFindSymbol(handle, DEBUGGER_SYMBOL_NAME);
    if (!symbol) {
        LOGE("failed to find symbol: %{public}s", DEBUGGER_SYMBOL_NAME);
        DynamicFreeLibrary(handle);
        return false;
    }
    auto func = reinterpret_cast<bool (*)(int, const std::string&)>(symbol);
    std::string name = "PandaDebugger";
    func(0, name);
    return true;
}

std::vector<uint32_t> SplitVersion(std::string& version, char separator)
{
    std::vector<uint32_t> result;
    std::stringstream ss(version);
    std::string item;

    while (std::getline(ss, item, separator)) {
        result.push_back(std::stoul(item));
    }
    return result;
}

CJEnvironment::NSMode CJEnvironment::DetectAppNSMode()
{
    LOGI("App compileSDKVersion is %{public}s", CJEnvironment::appVersion.c_str());
    std::vector<uint32_t> tokens = SplitVersion(CJEnvironment::appVersion, '.');
    if (tokens[0] > CJEnvironment::majorVersion ||
        (tokens[0] == CJEnvironment::majorVersion && tokens[1] >= CJEnvironment::minorVersion)) {
        return NSMode::SINK;
    } else {
        return NSMode::APP;
    }
}

void CJEnvironment::InitRuntimeNS()
{
#ifdef __OHOS__
    if (nsMode_ == NSMode::APP) {
        InitNewCJChipSDKNS(CJ_CHIPSDK_PATH);
        InitCJSDKNS(CJ_RT_PATH + ":" + CJ_LIB_PATH);
    } else {
        InitNewCJSDKNS(CJ_SDK_PATH);
        InitCJCompatibilitySDKNS(CJ_RT_PATH + ":" + CJ_LIB_PATH);
    }
#endif
}

void CJEnvironment::InitCJNS(const std::string& appPath)
{
#ifdef __OHOS__
    InitNewCJAppNS(appPath.empty() ? SANDBOX_LIB_PATH : appPath);
#endif
    StartRuntime();
    StartUIScheduler();
}

void CJEnvironment::SetAppVersion(std::string& version)
{
    CJEnvironment::appVersion = version;
}

CJEnvMethods* CJEnvironment::CreateEnvMethods()
{
    static CJEnvMethods gCJEnvMethods {
        .initCJAppNS = [](const std::string& path) {
            // to keep compatibility with older version
            CJEnvironment::SetAppPath(path);
        },
        .initCJSDKNS = [](const std::string& path) {
            // @deprecated
        },
        .initCJSysNS = [](const std::string& path) {
            // @deprecated
        },
        .initCJChipSDKNS = [](const std::string& path) {
            // @deprecated
        },
        .startRuntime = [] {
            return CJEnvironment::GetInstance()->StartRuntime();
        },
        .startUIScheduler = [] {
            return CJEnvironment::GetInstance()->StartUIScheduler();
        },
        .loadCJModule = [](const char* dllName) {
            return CJEnvironment::GetInstance()->LoadCJLibrary(dllName);
        },
        .loadLibrary = [](uint32_t kind, const char* dllName) {
            return CJEnvironment::GetInstance()->LoadCJLibrary(static_cast<CJEnvironment::LibraryKind>(kind), dllName);
        },
        .getSymbol = [](void* handle, const char* dllName) {
            return CJEnvironment::GetInstance()->GetSymbol(handle, dllName);
        },
        .loadCJLibrary = [](const char* dllName) {
            return CJEnvironment::GetInstance()->LoadCJLibrary(dllName);
        },
        .startDebugger = []() {
            return CJEnvironment::GetInstance()->StartDebugger();
        },
        .registerCJUncaughtExceptionHandler = [](const CJUncaughtExceptionInfo& handle) {
            return CJEnvironment::GetInstance()->RegisterCJUncaughtExceptionHandler(handle);
        },
        .setSanitizerKindRuntimeVersion = [](SanitizerKind kind) {
            return CJEnvironment::GetInstance()->SetSanitizerKindRuntimeVersion(kind);
        },
        .checkLoadCJLibrary = []() {
            return CJEnvironment::GetInstance()->CheckLoadCJLibrary();
        },
        .registerArkVMInRuntime = [](unsigned long long arkVM) {
            CJEnvironment::GetInstance()->RegisterArkVMInRuntime(arkVM);
        },
        .registerStackInfoCallbacks = [](UpdateStackInfoFuncType uFunc) {
            CJEnvironment::GetInstance()->RegisterStackInfoCallbacks(uFunc);
        },
        .setAppVersion = [](std::string& version) {
            CJEnvironment::SetAppVersion(version);
        },
        .dumpHeapSnapshot = [](int fd) {
            CJEnvironment::GetInstance()->DumpHeapSnapshot(fd);
        },
        .forceFullGC = []() {
            CJEnvironment::GetInstance()->ForceFullGC();
        }
    };
    return &gCJEnvMethods;
}

CJ_EXPORT extern "C" void OHOS_InitSpawnEnv()
{
    CJEnvironment::InitSpawnEnv();
}

CJ_EXPORT extern "C" CJEnvMethods* OHOS_GetCJEnvInstance()
{
    return CJEnvironment::CreateEnvMethods();
}
}
