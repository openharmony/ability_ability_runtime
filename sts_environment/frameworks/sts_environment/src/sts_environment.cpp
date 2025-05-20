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
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>

#include "dynamic_loader.h"
#include "elf_factory.h"
#include "event_handler.h"
#include "hilog_tag_wrapper.h"
#include "sts_hilog.h"
#include "sts_invoker.h"
#include "unwinder.h"

#ifdef SUPPORT_GRAPHICS
#include "ui_content.h"
#endif // SUPPORT_GRAPHICS

namespace OHOS {
namespace StsEnv {
const char STS_GET_DEFAULT_VM_INIT_ARGS[] = "ETS_GetDefaultVMInitArgs";
const char STS_GET_CREATED_VMS[] = "ETS_GetCreatedVMs";
const char STS_CREATE_VM[] = "ANI_CreateVM";
const char STS_ANI_GET_CREATEDVMS[] = "ANI_GetCreatedVMs";
const char STS_LIB_PATH[] = "libets_interop_js_napi.z.so";
const char BOOT_PATH[] = "/system/framework/bootpath.json";
const char BACKTRACE[] = "=====================Backtrace========================";


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

std::string STSEnvironment::GetBuildId(std::string stack)
{
    std::stringstream ss(stack);
    std::string tempStr;
    std::string addBuildId;
    int i = 0;
    while (std::getline(ss, tempStr)) {
        auto spitlPos = tempStr.rfind(" ");
        if (spitlPos != std::string::npos) {
            HiviewDFX::RegularElfFactory elfFactory(tempStr.substr(spitlPos + 1));
            auto elfFile = elfFactory.Create();
            std::string buildId = elfFile->GetBuildId();
            if (i != 0 && !buildId.empty()) {
                addBuildId += tempStr + "(" + buildId + ")" + "\n";
            } else {
                addBuildId += tempStr + "\n";
            }
        }
        i++;
    }
    return addBuildId;
}

void STSEnvironment::RegisterUncaughtExceptionHandler(const STSUncaughtExceptionInfo& handle)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    uncaughtExceptionInfo_ = handle;
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

bool STSEnvironment::StartRuntime(napi_env napiEnv, std::vector<ani_option>& options)
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
    std::string bootString = optionPrefix + "--boot-panda-files=" + bootfiles;
    TAG_LOGI(AAFwkTag::STSRUNTIME, "bootString %{public}s", bootString.c_str());
    options.push_back(ani_option{bootString.c_str(), nullptr});
    std::string schedulingExternal = optionPrefix + "--coroutine-enable-external-scheduling=true";
    ani_option schedulingExternalOption = {schedulingExternal.data(), nullptr};
    options.push_back(schedulingExternalOption);

    std::string forbiddenJIT = optionPrefix + "--compiler-enable-jit=false";
    ani_option forbiddenJITOption = {forbiddenJIT.data(), nullptr};
    options.push_back(forbiddenJITOption);

    options.push_back(ani_option{"--ext:--log-level=info", nullptr});

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
    if (vmEntry_.ani_vm == nullptr) {
        return nullptr;
    }
    ani_env* env = nullptr;
    if (vmEntry_.ani_vm->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        return nullptr;
    }
    return env;
}

void STSEnvironment::HandleUncaughtError()
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    const StsEnv::STSErrorObject errorObj = GetSTSErrorObject();
    std::string errorStack = errorObj.stack;
    if (errorStack.empty()) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "errorStack is empty");
        return;
    }
    TAG_LOGE(AAFwkTag::STSRUNTIME, "errorObj.name:%{public}s, errorObj.message:%{public}s,errorObj.stack:%{public}s",
        errorObj.name.c_str(), errorObj.message.c_str(), errorObj.stack.c_str());
    std::string summary = "Error name:" + errorObj.name + "\n";
    summary += "Error message:" + errorObj.message + "\n";
    if (errorStack.find(BACKTRACE) != std::string::npos) {
        summary += "Stacktrace:\n" + GetBuildId(errorStack);
    } else {
        summary += "Stacktrace:\n" + errorStack;
    }
#ifdef SUPPORT_GRAPHICS
    std::string str = Ace::UIContent::GetCurrentUIStackInfo();
    if (!str.empty()) {
        summary.append(str);
    }
#endif // SUPPORT_GRAPHICS
    if (uncaughtExceptionInfo_.uncaughtTask) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "uncaughtTask called");
        uncaughtExceptionInfo_.uncaughtTask(summary, errorObj);
    }
}

StsEnv::STSErrorObject STSEnvironment::GetSTSErrorObject()
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    ani_boolean errorExists = ANI_FALSE;
    ani_status status = ANI_ERROR;
    auto aniEnv = GetAniEnv();
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "null env");
        return StsEnv::STSErrorObject();
    }
    if ((status = aniEnv->ExistUnhandledError(&errorExists)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "ExistUnhandledError failed, status : %{public}d", status);
        return StsEnv::STSErrorObject();
    }
    if (errorExists == ANI_FALSE) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "not exist error");
        return StsEnv::STSErrorObject();
    }
    ani_error aniError = nullptr;
    if ((status = aniEnv->GetUnhandledError(&aniError)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "GetUnhandledError failed, status : %{public}d", status);
        return StsEnv::STSErrorObject();
    }
    if ((status = aniEnv->ResetError()) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "ResetError failed, status : %{public}d", status);
        return StsEnv::STSErrorObject();
    }
    std::string errorMsg = GetErrorProperty(aniError, "message");
    std::string errorName = GetErrorProperty(aniError, "name");
    std::string errorStack = GetErrorProperty(aniError, "stack");
    const StsEnv::STSErrorObject errorObj = {
        .name = errorName,
        .message = errorMsg,
        .stack = errorStack
    };
    return errorObj;
}

std::string STSEnvironment::GetErrorProperty(ani_error aniError, const char* property)
{
    TAG_LOGD(AAFwkTag::STSRUNTIME, "called");
    auto aniEnv = GetAniEnv();
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "null env");
        return "";
    }
    std::string propertyValue;
    ani_status status = ANI_ERROR;
    ani_type errorType = nullptr;
    if ((status = aniEnv->Object_GetType(aniError, &errorType)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Object_GetType failed, status : %{public}d", status);
        return propertyValue;
    }
    ani_method getterMethod = nullptr;
    if ((status = aniEnv->Class_FindGetter(static_cast<ani_class>(errorType), property, &getterMethod)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Class_FindGetter failed, status : %{public}d", status);
        return propertyValue;
    }
    ani_ref aniRef = nullptr;
    if ((status = aniEnv->Object_CallMethod_Ref(aniError, getterMethod, &aniRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Object_CallMethod_Ref failed, status : %{public}d", status);
        return propertyValue;
    }
    ani_string aniString = reinterpret_cast<ani_string>(aniRef);
    ani_size sz {};
    if ((status = aniEnv->String_GetUTF8Size(aniString, &sz)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "String_GetUTF8Size failed, status : %{public}d", status);
        return propertyValue;
    }
    propertyValue.resize(sz + 1);
    if ((status = aniEnv->String_GetUTF8SubString(
        aniString, 0, sz, propertyValue.data(), propertyValue.size(), &sz))!= ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "String_GetUTF8SubString failed, status : %{public}d", status);
        return propertyValue;
    }
    propertyValue.resize(sz);
    return propertyValue;
}
} // namespace StsEnv
} // namespace OHOS
