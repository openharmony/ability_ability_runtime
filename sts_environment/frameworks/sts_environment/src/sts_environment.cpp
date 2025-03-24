/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <thread>
#include <chrono>

#include "dynamic_loader.h"
#include "event_handler.h"
#include "hilog_tag_wrapper.h"
#include "sts_hilog.h"
#include "sts_invoker.h"

namespace OHOS {
namespace StsEnv {
const char STS_GET_DEFAULT_VM_INIT_ARGS[] = "ETS_GetDefaultVMInitArgs";
const char STS_GET_CREATED_VMS[] = "ETS_GetCreatedVMs";
const char STS_CREATE_VM[] = "ANI_CreateVM";
const char STS_ANI_GET_CREATEDVMS[] = "ANI_GetCreatedVMs";
const char STS_LIB_PATH[] = "libarkruntime.so";
const char BOOT_PATH[] = "/system/framework/bootpath.json";

using GetDefaultVMInitArgsSTSRuntimeType = ets_int (*)(EtsVMInitArgs* vmArgs);
using GetCreatedVMsSTSRuntimeType = ets_int (*)(EtsVM** vmBuf, ets_size bufLen, ets_size* nVms);
using CreateVMSTSRuntimeType = ani_status (*)(const ani_options *options, uint32_t version, ani_vm **result);
using ANIGetCreatedVMsType = ani_status (*)(ani_vm **vms_buffer, ani_size vms_buffer_length, ani_size *result);

const char* STSEnvironment::stsAppNSName = "sts_app";
const char* STSEnvironment::stsSDKNSName = "sts_sdk";
const char* STSEnvironment::stsSysNSName = "sts_system";
const char* STSEnvironment::stsChipSDKNSName = "sts_chipsdk";

STSRuntimeAPI STSEnvironment::lazyApis_{};

bool STSEnvironment::LoadBootPathFile(std::string& bootfiles)
{
    std::ifstream inFile;
    inFile.open(BOOT_PATH, std::ios::in);
    if (!inFile.is_open()) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "read json error");
        return false;
    }
    nlohmann::json jsonObject = nlohmann::json::parse(inFile);
    if (jsonObject.is_discarded()) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "json discarded error");
        inFile.close();
        return false;
    }

    if (jsonObject.is_null() || jsonObject.empty()) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "invalid json");
        inFile.close();
        return false;
    }

    for (const auto &[key, value] : jsonObject.items()) {
      if (!value.is_null() && value.is_string()) {
            std::string jsonValue = value.get<std::string>();
            if (jsonValue.empty()) {
                TAG_LOGE(AAFwkTag::STSRUNTIME, "json value of %{public}s is empty", key.c_str());
                continue;
            }
            if (!bootfiles.empty()) {
                bootfiles += ":";
            }
            bootfiles += jsonValue.c_str();
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
}

bool STSEnvironment::PostTask(TaskFuncType task)
{
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
    apis.ANI_CreateVM = reinterpret_cast<CreateVMSTSRuntimeType>(symbol);

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

void STSEnvironment::InitSTSSDKNS(const std::string& path)
{
    LOGI("InitSTSSDKNS: %{public}s", path.c_str());
    Dl_namespace sts_app;
    Dl_namespace ns;
    dlns_get(STSEnvironment::stsAppNSName, &sts_app);
    DynamicInitNamespace(&ns, &sts_app, path.c_str(), STSEnvironment::stsSDKNSName);
}

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

bool STSEnvironment::StartRuntime(napi_env napiEnv)
{
    TAG_LOGE(AAFwkTag::STSRUNTIME, "StartRuntime call");
    if (isRuntimeStarted_) {
        return true;
    }
    if (!LoadRuntimeApis()) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "LoadRuntimeApis failed");
        return false;
    }
    std::string bootfiles;
    if (!LoadBootPathFile(bootfiles)) {
        TAG_LOGE(AAFwkTag::STSRUNTIME,"LoadBootPathFile failed");
        return false;
    }

    const std::string optionPrefix = "--ext:";
    // Create boot-panda-files options
    std::vector<ani_option> options;
    std::string bootString = optionPrefix + "--boot-panda-files=" + bootfiles;
    TAG_LOGI(AAFwkTag::STSRUNTIME, "bootString %{public}s", bootString.c_str());
    options.push_back(ani_option{bootString.c_str(), nullptr});

    // std::string bootStringAsyn = optionPrefix + "--coroutine-enable-features:ani-drain-queue";
    // options.push_back(ani_option{bootStringAsyn.c_str(), nullptr});
    std::string schedulingExternal = optionPrefix + "--coroutine-enable-external-scheduling=true";
    ani_option schedulingExternalOption = {schedulingExternal.data(), nullptr};
    options.push_back(schedulingExternalOption);

    std::string forbiddenJIT = optionPrefix + "--compiler-enable-jit=false";
    ani_option forbiddenJITOption = {forbiddenJIT.data(), nullptr};
    options.push_back(forbiddenJITOption);

    options.push_back(ani_option{"--ext:--log-level=info", nullptr});

    std::string enableVerfication = optionPrefix + "--verification-enabled=true";
    ani_option enableVerficationOption = {enableVerfication.data(), nullptr};
    options.push_back(enableVerficationOption);

    std::string verificationMode = optionPrefix + "--verification-mode=on-the-fly";
    ani_option verificationModeOption = {verificationMode.data(), nullptr};
    options.push_back(verificationModeOption);

    std::string interop = optionPrefix + "interop";
    ani_option interopOption = {interop.data(), (void*)napiEnv};
    options.push_back(interopOption);

    ani_options optionsPtr = {options.size(), options.data()};
    auto status = lazyApis_.ANI_CreateVM(&optionsPtr, ANI_VERSION_1, &vmEntry_.ani_vm);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "ANI_CreateVM failed %{public}d", status);
        return false;
    }
 
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
}

bool STSEnvironment::StartUIScheduler()
{
    return true;
}

void STSEnvironment::StopUIScheduler()
{
}

void* STSEnvironment::LoadSTSLibrary(const char* dlName)
{
    return nullptr;
}

void STSEnvironment::UnLoadSTSLibrary(void* handle)
{
    DynamicFreeLibrary(handle);
}

bool STSEnvironment::StartDebugger()
{
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
