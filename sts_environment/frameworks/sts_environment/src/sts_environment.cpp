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

#include "sts_environment.h"

#include <dlfcn.h>
#include <fstream>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#include "dynamic_loader.h"
#include "event_handler.h"
#include "hilog_tag_wrapper.h"
#include "sts_hilog.h"
#include "sts_invoker.h"

namespace OHOS {
namespace StsEnv {
const char STS_GET_DEFAULT_VM_INIT_ARGS[] = "ETS_GetDefaultVMInitArgs";
const char STS_GET_CREATED_VMS[] = "ETS_GetCreatedVMs";
const char STS_CREATE_VM[] = "ETS_CreateVM";
const char STS_ANI_GET_CREATEDVMS[] = "ANI_GetCreatedVMs";
const char STS_LIB_PATH[] = "libarkruntime.so";
const char STS_STD_LIB_PATH[] = "/system/etc/etsstdlib.abc";
const char BOOT_PATH[] = "/system/etc/bootpath.json";
const char STS_ARK_UI_PATH_KEY[] = "arkui";
const char STS_ARK_COMPILER_PATH_KEY[] = "arkcompiler";
const char STS_WINDOW_PATH_KEY[] = "window";
const char STS_FIX_ARRAY_PATH_KEY[] = "fixarray";

using GetDefaultVMInitArgsSTSRuntimeType = ets_int (*)(EtsVMInitArgs* vmArgs);
using GetCreatedVMsSTSRuntimeType = ets_int (*)(EtsVM** vmBuf, ets_size bufLen, ets_size* nVms);
using CreateVMSTSRuntimeType = ets_int (*)(EtsVM** pVm, EtsEnv** pEnv, EtsVMInitArgs* vmArgs);
using ANIGetCreatedVMsType = ani_status (*)(ani_vm **vms_buffer, ani_size vms_buffer_length, ani_size *result);

const char* STSEnvironment::stsAppNSName = "sts_app";
const char* STSEnvironment::stsSDKNSName = "sts_sdk";
const char* STSEnvironment::stsSysNSName = "sts_system";
const char* STSEnvironment::stsChipSDKNSName = "sts_chipsdk";

STSRuntimeAPI STSEnvironment::lazyApis_{};

bool STSEnvironment::LoadBootPathFile(std::vector<EtsVMOption> &etsVMOptions)
{
    std::vector<std::string> pathFiles;
    pathFiles.push_back(std::string(STS_ARK_UI_PATH_KEY));
    pathFiles.push_back(std::string(STS_ARK_COMPILER_PATH_KEY));
    pathFiles.push_back(std::string(STS_WINDOW_PATH_KEY));
    pathFiles.push_back(std::string(STS_FIX_ARRAY_PATH_KEY));

    std::ifstream inFile;
    inFile.open(BOOT_PATH, std::ios::in);
    if (!inFile.is_open()) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "read json error");
        return false;
    }
    nlohmann::json filePathsJson;
    inFile >> filePathsJson;
    if (filePathsJson.is_discarded()) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "json discarded error");
        inFile.close();
        return false;
    }

    if (filePathsJson.is_null() || filePathsJson.empty()) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "invalid json");
        inFile.close();
        return false;
    }

    for (auto& pathFile : pathFiles) {
        if (!filePathsJson.contains(pathFile)) {
            continue;
        }
        if (!filePathsJson[pathFile].is_null() && filePathsJson[pathFile].is_string()) {
            std::string jsonValue = filePathsJson[pathFile].get<std::string>();
            if (jsonValue.empty()) {
                TAG_LOGE(AAFwkTag::STSRUNTIME, "json value of %{public}s is empty", pathFile.c_str());
                continue;
            }
            std::ifstream abcfile(jsonValue);
            if (!abcfile.good()) {
                TAG_LOGE(AAFwkTag::STSRUNTIME, "file is not exist: %{public}s", jsonValue.c_str());
                continue;
            }
            TAG_LOGI(AAFwkTag::STSRUNTIME, "load file: %{public}s", jsonValue.c_str());
            char* charArray = new char[jsonValue.size() + 1];
            std::strcpy(charArray, jsonValue.c_str());
            etsVMOptions.push_back({ EtsOptionType::ETS_BOOT_FILE, charArray });
        }
    }
    inFile.close();
    return true;
}

bool STSEnvironment::LoadRuntimeApis()
{
    static bool isRuntimeApiLoaded{ false };
    if (isRuntimeApiLoaded) {
        return true;
    }

    Dl_namespace ns;
    dlns_get(STSEnvironment::stsSDKNSName, &ns);
    auto dso = DynamicLoadLibrary(&ns, STS_LIB_PATH, 1);
    if (!dso) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "load library failed: %{public}s", STS_LIB_PATH);
        return false;
    }

    if (!LoadSymbolGetDefaultVMInitArgs(dso, lazyApis_) ||
	    !LoadSymbolGetCreatedVMs(dso, lazyApis_) ||
        !LoadSymbolCreateVM(dso, lazyApis_) ||
        !LoadSymbolANIGetCreatedVMs(dso, lazyApis_)) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "load symbol failed");
        return false;
    }

    isRuntimeApiLoaded = true;
    return true;
}

void STSEnvironment::RegisterUncaughtExceptionHandler(const STSUncaughtExceptionInfo& handle)
{
    // lazyApis_.RegisterCJUncaughtExceptionHandler(handle);
}

bool STSEnvironment::PostTask(TaskFuncType task)
{
    // #ifdef WITH_EVENT_HANDLER
    //     if (task == nullptr) {
    //         TAG_LOGE(AAFwkTag::STSRUNTIME, "null task could not be posted");
    //         return false;
    //     }

    //     bool postDone = g_handler->PostTask(task, "spawn-main-task-from-cj", 0,
    //     AppExecFwk::EventQueue::Priority::HIGH); if (!postDone) {
    //         TAG_LOGE(AAFwkTag::STSRUNTIME, "event handler support cj ui scheduler");
    //         return false;
    //     }
    //     return true;
    // #endif
    return true;
}

bool STSEnvironment::LoadSymbolGetDefaultVMInitArgs(void* handle, STSRuntimeAPI& apis)
{
    auto symbol = dlsym(handle, STS_GET_DEFAULT_VM_INIT_ARGS);
    if (symbol == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "runtime api not found: %{public}s", STS_GET_DEFAULT_VM_INIT_ARGS);
        return false;
    }
    apis.ETS_GetDefaultVMInitArgs = reinterpret_cast<GetDefaultVMInitArgsSTSRuntimeType>(symbol);

    return true;
}

bool STSEnvironment::LoadSymbolGetCreatedVMs(void* handle, STSRuntimeAPI& apis)
{
    auto symbol = dlsym(handle, STS_GET_CREATED_VMS);
    if (symbol == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "runtime api not found: %{public}s", STS_GET_CREATED_VMS);
        return false;
    }
    apis.ETS_GetCreatedVMs = reinterpret_cast<GetCreatedVMsSTSRuntimeType>(symbol);

    return true;
}

bool STSEnvironment::LoadSymbolCreateVM(void* handle, STSRuntimeAPI& apis)
{
    auto symbol = dlsym(handle, STS_CREATE_VM);
    if (symbol == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "runtime api not found: %{public}s", STS_CREATE_VM);
        return false;
    }
    apis.ETS_CreateVM = reinterpret_cast<CreateVMSTSRuntimeType>(symbol);

    return true;
}

bool STSEnvironment::LoadSymbolANIGetCreatedVMs(void* handle, STSRuntimeAPI& apis)
{
    auto symbol = dlsym(handle, STS_ANI_GET_CREATEDVMS);
    if (symbol == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "runtime api not found: %{public}s", STS_ANI_GET_CREATEDVMS);
        return false;
    }
    apis.ANI_GetCreatedVMs = reinterpret_cast<ANIGetCreatedVMsType>(symbol);

    return true;
}

void STSEnvironment::InitSTSChipSDKNS(const ::std::string& path)
{
    LOGI("InitSTSChipSDKNS: %{public}s", path.c_str());
    Dl_namespace chip_ndk;
    DynamicInitNamespace(&chip_ndk, nullptr, path.c_str(), STSEnvironment::stsChipSDKNSName);

    Dl_namespace ndk;
    Dl_namespace current;
    dlns_get(nullptr, &current);
    dlns_get("ndk", &ndk);
    dlns_inherit(&chip_ndk, &ndk, "allow_all_shared_libs");
    dlns_inherit(&chip_ndk, &current, "allow_all_shared_libs");
}

// Init app namespace
void STSEnvironment::InitSTSAppNS(const std::string& path)
{
    LOGI("InitSTSAppNS: %{public}s", path.c_str());
    Dl_namespace ndk;
    Dl_namespace ns;
    DynamicInitNamespace(&ns, nullptr, path.c_str(), STSEnvironment::stsAppNSName);
    dlns_get("ndk", &ndk);
    dlns_inherit(&ns, &ndk, "allow_all_shared_libs");
    Dl_namespace current;
    dlns_get(nullptr, &current);
    dlns_inherit(&ndk, &current, "allow_all_shared_libs");
    dlns_inherit(&current, &ndk, "allow_all_shared_libs");
}

// Init sts sdk namespace
void STSEnvironment::InitSTSSDKNS(const std::string& path)
{
    LOGI("InitSTSSDKNS: %{public}s", path.c_str());
    Dl_namespace sts_app;
    Dl_namespace ns;
    dlns_get(STSEnvironment::stsAppNSName, &sts_app);
    DynamicInitNamespace(&ns, &sts_app, path.c_str(), STSEnvironment::stsSDKNSName);
}

// Init sts system namespace
void STSEnvironment::InitSTSSysNS(const std::string& path)
{
    LOGI("InitSTSSysNS: %{public}s", path.c_str());
    Dl_namespace sts_sdk;
    Dl_namespace ndk;
    Dl_namespace ns;
    dlns_get(STSEnvironment::stsSDKNSName, &sts_sdk);
    DynamicInitNamespace(&ns, &sts_sdk, path.c_str(), STSEnvironment::stsSysNSName);
    dlns_get("ndk", &ndk);
    dlns_inherit(&ns, &ndk, "allow_all_shared_libs");
}

bool STSEnvironment::StartRuntime()
{
    TAG_LOGE(AAFwkTag::STSRUNTIME, "StartRuntime call");
    if (isRuntimeStarted_) {
        return true;
    }
    if (!LoadRuntimeApis()) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "LoadRuntimeApis failed");
        return false;
    }
    std::vector<EtsVMOption> etsVMOptions;
    if (!LoadBootPathFile(etsVMOptions)) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "LoadBootPathFile failed");
        return false;
    }
    etsVMOptions.push_back({ EtsOptionType::ETS_BOOT_FILE, STS_STD_LIB_PATH });
    TAG_LOGE(AAFwkTag::STSRUNTIME, "etsVMOptions.size() = %{public}d", etsVMOptions.size());
    // etsVMOptions.push_back({ EtsOptionType::ETS_BOOT_FILE, "/data/storage/el1/bundle/lib/modules.static.abc" });   // for Test
    // etsVMOptions.push_back({ EtsOptionType::ETS_BOOT_FILE, "/system/lib/sts/EntryAbility.abc" });
    // etsVMOptions.push_back({ EtsOptionType::ETS_NATIVE_LIBRARY_PATH, (char*)strdup(std::string(appLibPath).c_str())
    // });

    // TODO: for test
    // etsVMOptions.push_back({ EtsOptionType::ETS_BOOT_FILE, "/system/lib64/sts/ability_delegator.abc" });

    etsVMOptions.push_back({ EtsOptionType::ETS_VERIFICATION_MODE, "on-the-fly" });
    etsVMOptions.push_back({ EtsOptionType::ETS_NO_JIT, nullptr });
    // etsVMOptions.push_back({ EtsOptionType::ETS_MOBILE_LOG, (void*)ArkMobileLog });
    EtsVMInitArgs vmArgs;
    vmArgs.version = ETS_NAPI_VERSION_1_0;
    vmArgs.options = etsVMOptions.data();
    vmArgs.nOptions = etsVMOptions.size();
    EtsVM* vm = { nullptr };
    EtsEnv* env = { nullptr };
    if (lazyApis_.ETS_CreateVM(&vm, &env, &vmArgs) != ETS_OK) {
        return false;
    }
    vmEntry_.vm = vm;
    vmEntry_.env = env;
    ani_size nrVMs;
    if (lazyApis_.ANI_GetCreatedVMs(&vmEntry_.ani_vm, 1, &nrVMs) != ANI_OK) {
        return false;
    };
    if (vmEntry_.ani_vm->GetEnv(ANI_VERSION_1, &vmEntry_.ani_env) != ANI_OK) {
        return false;
    }
    isRuntimeStarted_ = true;
    return true;
}

void STSEnvironment::StopRuntime()
{
    if (!isRuntimeStarted_) {
        return;
    }

    // if (isUISchedulerStarted_) {
    //     StopUIScheduler();
    // }

    // auto code = lazyApis_.FiniCJRuntime();
    // if (code == E_OK) {
    //     isRuntimeStarted_ = false;
    // }
}

bool STSEnvironment::StartUIScheduler()
{
    // if (isUISchedulerStarted_) {
    //     return true;
    // }

    // uiScheduler_ = lazyApis_.InitUIScheduler();
    // if (!uiScheduler_) {
    //     TAG_LOGE(AAFwkTag::STSRUNTIME, "init cj ui scheduler failed");
    //     return false;
    // }

    // isUISchedulerStarted_ = true;
    return true;
}

void STSEnvironment::StopUIScheduler()
{
    // isUISchedulerStarted_ = false;
}

void* STSEnvironment::LoadSTSLibrary(const char* dlName)
{
    // if (!StartRuntime()) {
    //     TAG_LOGE(AAFwkTag::STSRUNTIME, "StartRuntime failed");
    //     return nullptr;
    // }
    // auto handle = LoadSTSLibrary(APP, dlName);
    // if (!handle) {
    //     TAG_LOGE(AAFwkTag::STSRUNTIME, "load cj library failed: %{public}s", DynamicGetError());
    //     return nullptr;
    // }

    // LOGI("LoadCJLibrary InitCJLibrary: %{public}s", dlName);
    // auto status = lazyApis_.InitCJLibrary(dlName);
    // if (status != E_OK) {
    //     TAG_LOGE(AAFwkTag::STSRUNTIME, "InitCJLibrary failed: %{public}s", dlName);
    //     UnLoadCJLibrary(handle);
    //     return nullptr;
    // }

    // isLoadCJLibrary_ = true;
    // return handle;
    return nullptr;
}

void STSEnvironment::UnLoadSTSLibrary(void* handle)
{
    DynamicFreeLibrary(handle);
}

bool STSEnvironment::StartDebugger()
{
    // #ifdef __OHOS__
    //     Dl_namespace ns;
    //     dlns_get(CJEnvironment::cjSysNSName, &ns);
    //     auto handle = DynamicLoadLibrary(&ns, DEBUGGER_LIBNAME, 0);
    // #else
    //     auto handle = DynamicLoadLibrary(DEBUGGER_LIBNAME, 0);
    // #endif
    //     if (!handle) {
    //         TAG_LOGE(AAFwkTag::STSRUNTIME, "failed to load library: %{public}s", DEBUGGER_LIBNAME);
    //         return false;
    //     }
    //     auto symbol = DynamicFindSymbol(handle, DEBUGGER_SYMBOL_NAME);
    //     if (!symbol) {
    //         TAG_LOGE(AAFwkTag::STSRUNTIME, "failed to find symbol: %{public}s", DEBUGGER_SYMBOL_NAME);
    //         DynamicFreeLibrary(handle);
    //         return false;
    //     }
    //     auto func = reinterpret_cast<bool (*)(int, const std::string&)>(symbol);
    //     std::string name = "PandaDebugger";
    //     func(0, name);
    return true;
}

STSEnvironment::STSEnvironment(std::unique_ptr<StsEnvironmentImpl> impl) : impl_(std::move(impl))
{}

void STSEnvironment::PostTask(const std::function<void()>& task, const std::string& name, int64_t delayTime)
{
    LOGI("PostTask: %{public}s", name.c_str());
    if (impl_ != nullptr) {
        impl_->PostTask(task, name, delayTime);
    }
}

void STSEnvironment::PostSyncTask(const std::function<void()>& task, const std::string& name)
{
    LOGI("PostSyncTask: %{public}s", name.c_str());
    if (impl_ != nullptr) {
        impl_->PostSyncTask(task, name);
    }
}

void STSEnvironment::RemoveTask(const std::string& name)
{
    LOGI("RemoveTask: %{public}s", name.c_str());
    if (impl_ != nullptr) {
        impl_->RemoveTask(name);
    }
}

bool STSEnvironment::InitLoop(bool isStage){
    LOGI("InitLoop");
    if (impl_ != nullptr) {
        return impl_->InitLoop(isStage);
    }
    return false;
}

void STSEnvironment::DeInitLoop()
{
    LOGI("DeInitLoop");
    if (impl_ != nullptr) {
        impl_->DeInitLoop();
    }
}

bool STSEnvironment::ReInitUVLoop()
{
    LOGI("ReInitUVLoop");
    if (impl_ != nullptr) {
        return impl_->ReInitUVLoop();
    }
    return false;
}

EtsVM* STSEnvironment::GetEtsVM()
{
    return vmEntry_.vm;
}
EtsEnv* STSEnvironment::GetEtsEnv()
{
    return vmEntry_.env;
}

void STSEnvironment::ReInitStsEnvImpl(std::unique_ptr<StsEnvironmentImpl> impl)
{
    LOGI("ReInit stsenv impl");
    impl_ = std::move(impl);
}

ani_env* STSEnvironment::GetAniEnv()
{
    return vmEntry_.ani_env;
}
} // namespace StsEnv
} // namespace OHOS
