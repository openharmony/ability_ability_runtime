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

#include "ets_environment.h"

#include <chrono>
#include <dlfcn.h>
#include <fstream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "static_core/plugins/ets/runtime/ets_namespace_manager.h"

#include "dynamic_loader.h"
#include "elf_factory.h"
#include "event_handler.h"
#include "hilog_tag_wrapper.h"
#include "unwinder.h"

#ifdef SUPPORT_GRAPHICS
#include "ui_content.h"
#endif // SUPPORT_GRAPHICS

namespace OHOS {
namespace EtsEnv {
namespace {
const char ETS_CREATE_VM[] = "ANI_CreateVM";
const char ETS_ANI_GET_CREATEDVMS[] = "ANI_GetCreatedVMs";
const char ETS_LIB_PATH[] = "libets_interop_js_napi.z.so";
const char BOOT_PATH[] = "/system/framework/bootpath.json";
const char BACKTRACE[] = "=====================Backtrace========================";

using CreateVMETSRuntimeType = ani_status (*)(const ani_options *options, uint32_t version, ani_vm **result);
using ANIGetCreatedVMsType = ani_status (*)(ani_vm **vms_buffer, ani_size vms_buffer_length, ani_size *result);

const char ETS_SDK_NSNAME[] = "ets_sdk";
const char ETS_SYS_NSNAME[] = "ets_system";

constexpr const char* CLASSNAME_STRING = "Lstd/core/String;";
constexpr const char* CLASSNAME_LINKER = "Lstd/core/AbcRuntimeLinker;";
} // namespace

ETSRuntimeAPI ETSEnvironment::lazyApis_ {};
std::unique_ptr<ETSEnvironment> instance_ = nullptr;

std::unique_ptr<ETSEnvironment> &ETSEnvironment::GetInstance()
{
    if (instance_ == nullptr) {
        instance_ = std::make_unique<ETSEnvironment>();
    }
    return instance_;
}

bool ETSEnvironment::LoadBootPathFile(std::string &bootfiles)
{
    std::ifstream inFile;
    inFile.open(BOOT_PATH, std::ios::in);
    if (!inFile.is_open()) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "read json error");
        return false;
    }
    nlohmann::json jsonObject = nlohmann::json::parse(inFile);
    if (jsonObject.is_discarded()) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "json discarded error");
        inFile.close();
        return false;
    }

    if (jsonObject.is_null() || jsonObject.empty()) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "invalid json");
        inFile.close();
        return false;
    }

    for (const auto &[key, value] : jsonObject.items()) {
        if (!value.is_null() && value.is_string()) {
            std::string jsonValue = value.get<std::string>();
            if (jsonValue.empty()) {
                TAG_LOGE(AAFwkTag::ETSRUNTIME, "json value of %{public}s is empty", key.c_str());
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

bool ETSEnvironment::LoadRuntimeApis()
{
    static bool isRuntimeApiLoaded { false };
    if (isRuntimeApiLoaded) {
        return true;
    }

    Dl_namespace ns;
    dlns_get(ETS_SDK_NSNAME, &ns);
    auto dso = DynamicLoadLibrary(&ns, ETS_LIB_PATH, 1);
    if (!dso) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "load library failed: %{public}s", ETS_LIB_PATH);
        return false;
    }

    if (!LoadSymbolCreateVM(dso, lazyApis_) ||
        !LoadSymbolANIGetCreatedVMs(dso, lazyApis_)) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "load symbol failed");
        return false;
    }

    isRuntimeApiLoaded = true;
    return true;
}

std::string ETSEnvironment::GetBuildId(std::string stack)
{
    std::stringstream ss(stack);
    std::string tempStr = "";
    std::string addBuildId = "";
    int i = 0;
    while (std::getline(ss, tempStr)) {
        auto spitlPos = tempStr.rfind(" ");
        if (spitlPos != std::string::npos) {
            HiviewDFX::RegularElfFactory elfFactory(tempStr.substr(spitlPos + 1));
            auto elfFile = elfFactory.Create();
            if (elfFile == nullptr) {
                TAG_LOGE(AAFwkTag::ETSRUNTIME, "null elfFile");
                break;
            }
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

void ETSEnvironment::RegisterUncaughtExceptionHandler(const ETSUncaughtExceptionInfo &handle)
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "RegisterUncaughtExceptionHandler called");
    uncaughtExceptionInfo_ = handle;
}

bool ETSEnvironment::LoadSymbolCreateVM(void *handle, ETSRuntimeAPI &apis)
{
    auto symbol = dlsym(handle, ETS_CREATE_VM);
    if (symbol == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "runtime api not found: %{public}s", ETS_CREATE_VM);
        return false;
    }
    apis.ANI_CreateVM = reinterpret_cast<CreateVMETSRuntimeType>(symbol);

    return true;
}

bool ETSEnvironment::LoadSymbolANIGetCreatedVMs(void *handle, ETSRuntimeAPI &apis)
{
    auto symbol = dlsym(handle, ETS_ANI_GET_CREATEDVMS);
    if (symbol == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "runtime api not found: %{public}s", ETS_ANI_GET_CREATEDVMS);
        return false;
    }
    apis.ANI_GetCreatedVMs = reinterpret_cast<ANIGetCreatedVMsType>(symbol);

    return true;
}

void ETSEnvironment::InitETSSDKNS(const std::string &path)
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "InitETSSDKNS: %{public}s", path.c_str());
    Dl_namespace ndk;
    Dl_namespace ns;
    DynamicInitNamespace(&ns, nullptr, path.c_str(), ETS_SDK_NSNAME);
    dlns_get("ndk", &ndk);
    dlns_inherit(&ns, &ndk, "allow_all_shared_libs");
}

void ETSEnvironment::InitETSSysNS(const std::string &path)
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "InitETSSysNS: %{public}s", path.c_str());
    Dl_namespace ets_sdk;
    Dl_namespace ndk;
    Dl_namespace ns;
    dlns_get(ETS_SDK_NSNAME, &ets_sdk);
    DynamicInitNamespace(&ns, &ets_sdk, path.c_str(), ETS_SYS_NSNAME);
    dlns_get("ndk", &ndk);
    dlns_inherit(&ns, &ndk, "allow_all_shared_libs");
}

bool ETSEnvironment::Initialize(void *napiEnv, const std::string &aotPath)
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "Initialize called");
    if (!LoadRuntimeApis()) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "LoadRuntimeApis failed");
        return false;
    }
    std::string bootfiles;
    if (!LoadBootPathFile(bootfiles)) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "LoadBootPathFile failed");
        return false;
    }

    std::vector<ani_option> options;
    std::string aotPathString = "";
    if (!aotPath.empty()) {
        aotPathString = "--ext:--aot-file=" + aotPath;
        options.push_back(ani_option { aotPathString.data(), nullptr });
        options.push_back(ani_option { "--ext:--enable-an", nullptr });
        TAG_LOGD(AAFwkTag::ETSRUNTIME, "aotPathString: %{public}s", aotPathString.c_str());
    }
    // Create boot-panda-files options
    std::string bootString = "--ext:--boot-panda-files=" + bootfiles;
    options.push_back(ani_option { bootString.data(), nullptr });
    options.push_back(ani_option { "--ext:--coroutine-enable-external-scheduling=true", nullptr });
    options.push_back(ani_option { "--ext:--compiler-enable-jit=false", nullptr });
    options.push_back(ani_option { "--ext:--log-level=info", nullptr });
    options.push_back(ani_option { "--ext:--verification-enabled=true", nullptr });
    options.push_back(ani_option { "--ext:--verification-mode=on-the-fly", nullptr });
    options.push_back(ani_option { "--ext:interop", napiEnv });
    ani_options optionsPtr = { options.size(), options.data() };
    ani_status status = ANI_ERROR;
    if ((status = lazyApis_.ANI_CreateVM(&optionsPtr, ANI_VERSION_1, &vmEntry_.aniVm_)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "ANI_CreateVM failed %{public}d", status);
        return false;
    }
    if ((status = vmEntry_.aniVm_->GetEnv(ANI_VERSION_1, &vmEntry_.aniEnv_)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "GetEnv failed %{public}d", status);
        return false;
    }
    return true;
}

ani_env *ETSEnvironment::GetAniEnv()
{
    if (vmEntry_.aniVm_ == nullptr) {
        return nullptr;
    }
    ani_env* env = nullptr;
    if (vmEntry_.aniVm_->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        return nullptr;
    }
    return env;
}

bool ETSEnvironment::HandleUncaughtError()
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "HandleUncaughtError called");
    const EtsEnv::ETSErrorObject errorObj = GetETSErrorObject();
    std::string errorStack = errorObj.stack;
    if (errorStack.empty()) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "errorStack is empty");
        return false;
    }
    TAG_LOGE(AAFwkTag::ETSRUNTIME, "errorObj.name:%{public}s, errorObj.message:%{public}s,errorObj.stack:%{public}s",
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
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "uncaughtTask called");
        uncaughtExceptionInfo_.uncaughtTask(summary, errorObj);
        return true;
    }
    return false;
}

EtsEnv::ETSErrorObject ETSEnvironment::GetETSErrorObject()
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "GetETSErrorObject called");
    ani_boolean errorExists = ANI_FALSE;
    ani_status status = ANI_ERROR;
    auto aniEnv = GetAniEnv();
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null env");
        return EtsEnv::ETSErrorObject();
    }
    if ((status = aniEnv->ExistUnhandledError(&errorExists)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "ExistUnhandledError failed, status : %{public}d", status);
        return EtsEnv::ETSErrorObject();
    }
    if (errorExists == ANI_FALSE) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "not exist error");
        return EtsEnv::ETSErrorObject();
    }
    ani_error aniError = nullptr;
    if ((status = aniEnv->GetUnhandledError(&aniError)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "GetUnhandledError failed, status : %{public}d", status);
        return EtsEnv::ETSErrorObject();
    }
    if ((status = aniEnv->ResetError()) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "ResetError failed, status : %{public}d", status);
        return EtsEnv::ETSErrorObject();
    }
    std::string errorMsg = GetErrorProperty(aniError, "message");
    std::string errorName = GetErrorProperty(aniError, "name");
    std::string errorStack = GetErrorProperty(aniError, "stack");
    const EtsEnv::ETSErrorObject errorObj = {
        .name = errorName,
        .message = errorMsg,
        .stack = errorStack
    };
    return errorObj;
}

std::string ETSEnvironment::GetErrorProperty(ani_error aniError, const char *property)
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "GetErrorProperty called");
    auto aniEnv = GetAniEnv();
    std::string propertyValue;
    ani_status status = ANI_ERROR;
    ani_type errorType = nullptr;
    if ((status = aniEnv->Object_GetType(aniError, &errorType)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Object_GetType failed, status : %{public}d", status);
        return propertyValue;
    }
    ani_method getterMethod = nullptr;
    if ((status = aniEnv->Class_FindGetter(static_cast<ani_class>(errorType), property, &getterMethod)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Class_FindGetter failed, status : %{public}d", status);
        return propertyValue;
    }
    ani_ref aniRef = nullptr;
    if ((status = aniEnv->Object_CallMethod_Ref(aniError, getterMethod, &aniRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Object_CallMethod_Ref failed, status : %{public}d", status);
        return propertyValue;
    }
    ani_string aniString = reinterpret_cast<ani_string>(aniRef);
    ani_size sz {};
    if ((status = aniEnv->String_GetUTF8Size(aniString, &sz)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "String_GetUTF8Size failed, status : %{public}d", status);
        return propertyValue;
    }
    propertyValue.resize(sz + 1);
    if ((status = aniEnv->String_GetUTF8SubString(
        aniString, 0, sz, propertyValue.data(), propertyValue.size(), &sz))!= ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "String_GetUTF8SubString failed, status : %{public}d", status);
        return propertyValue;
    }
    propertyValue.resize(sz);
    return propertyValue;
}

bool ETSEnvironment::PreloadModule(const std::string &modulePath)
{
    TAG_LOGD(AAFwkTag::ETSRUNTIME, "modulePath: %{public}s", modulePath.c_str());
    ani_env *env = GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null env");
        return false;
    }

    ani_class abcCls = nullptr;
    ani_object abcObj = nullptr;
    if (!LoadAbcLinker(env, modulePath, abcCls, abcObj)) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "LoadAbcLinker failed");
        return false;
    }
    return true;
}

bool ETSEnvironment::LoadAbcLinker(ani_env *env, const std::string &modulePath, ani_class &abcCls, ani_object &abcObj)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_class stringCls = nullptr;
    if ((status = env->FindClass(CLASSNAME_STRING, &stringCls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "FindClass failed, status: %{public}d", status);
        return false;
    }
    ani_string modulePathAni = nullptr;
    if ((status = env->String_NewUTF8(modulePath.c_str(), modulePath.size(), &modulePathAni)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "String_NewUTF8 failed, status: %{public}d", status);
        return false;
    }
    ani_ref undefinedRef = nullptr;
    if ((status = env->GetUndefined(&undefinedRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "GetUndefined failed, status: %{public}d", status);
        return false;
    }
    ani_array_ref refArray = nullptr;
    if ((status = env->Array_New_Ref(stringCls, 1, undefinedRef, &refArray)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Array_New_Ref failed, status: %{public}d", status);
        return false;
    }
    if ((status = env->Array_Set_Ref(refArray, 0, modulePathAni)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Array_Set_Ref failed, status: %{public}d", status);
        return false;
    }
    if ((status = env->FindClass(CLASSNAME_LINKER, &abcCls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "FindClass failed, status: %{public}d", status);
        return false;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(abcCls, "<ctor>", "Lstd/core/RuntimeLinker;[Lstd/core/String;:V",
        &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Class_FindMethod failed, status: %{public}d", status);
        return false;
    }
    env->ResetError();
    if ((status = env->Object_New(abcCls, method, &abcObj, undefinedRef, refArray)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Object_New failed, status: %{public}d", status);
        HandleUncaughtError();
        return false;
    }
    return true;
}

bool ETSEnvironment::LoadModule(const std::string &modulePath, const std::string &srcEntrance, void *&cls,
    void *&obj, void *&ref)
{
    ani_env *env = GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_class abcCls = nullptr;
    ani_object abcObj = nullptr;
    if (!LoadAbcLinker(env, modulePath, abcCls, abcObj)) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "LoadAbcLinker failed");
        return false;
    }
    ani_method loadClassMethod = nullptr;
    if ((status = env->Class_FindMethod(abcCls, "loadClass", nullptr, &loadClassMethod)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Class_FindMethod failed, status: %{public}d", status);
        return false;
    }
    ani_string clsStr = nullptr;
    if ((status = env->String_NewUTF8(srcEntrance.c_str(), srcEntrance.length(), &clsStr)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "String_NewUTF8 failed, status: %{public}d", status);
        return false;
    }
    ani_ref clsRef = nullptr;
    ani_class clsAni = nullptr;
    if ((status = env->Object_CallMethod_Ref(abcObj, loadClassMethod, &clsRef, clsStr, false)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Object_CallMethod_Ref failed, status: %{public}d", status);
        return false;
    }
    clsAni = static_cast<ani_class>(clsRef);
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(clsAni, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Class_FindMethod failed, status: %{public}d", status);
        return false;
    }
    ani_object objAni = nullptr;
    if ((status = env->Object_New(clsAni, method, &objAni)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Object_New failed, status: %{public}d", status);
        return false;
    }
    ani_ref refAni = nullptr;
    if ((status = env->GlobalReference_Create(objAni, &refAni)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "GlobalReference_Create failed, status: %{public}d", status);
        return false;
    }
    cls = reinterpret_cast<void *>(clsAni);
    obj = reinterpret_cast<void *>(objAni);
    ref = reinterpret_cast<void *>(refAni);
    return true;
}

ETSEnvFuncs *ETSEnvironment::RegisterFuncs()
{
    static ETSEnvFuncs funcs {
        .InitETSSDKNS = [](const std::string &path) {
            ETSEnvironment::InitETSSDKNS(path);
        },
        .InitETSSysNS = [](const std::string &path) {
            ETSEnvironment::InitETSSysNS(path);
        },
        .Initialize = [](void *napiEnv, const std::string &aotPath) {
            return ETSEnvironment::GetInstance()->Initialize(napiEnv, aotPath);
        },
        .RegisterUncaughtExceptionHandler = [](const ETSUncaughtExceptionInfo &exceptionInfo) {
            ETSEnvironment::GetInstance()->RegisterUncaughtExceptionHandler(exceptionInfo);
        },
        .GetAniEnv = []() {
            return ETSEnvironment::GetInstance()->GetAniEnv();
        },
        .PreloadModule = [](const std::string &modulePath) {
            return ETSEnvironment::GetInstance()->PreloadModule(modulePath);
        },
        .LoadModule = [](const std::string &modulePath, const std::string &srcEntrance, void *&cls,
             void *&obj,  void *&ref) {
            return ETSEnvironment::GetInstance()->LoadModule(modulePath, srcEntrance, cls, obj, ref);
        },
        .SetAppLibPath = [](const std::map<std::string, std::string> &abcPathsToBundleModuleNameMap,
            std::function<bool(const std::string &bundleModuleName, std::string &namespaceName)> &cb) {
            ark::ets::EtsNamespaceManager::SetAppLibPaths(abcPathsToBundleModuleNameMap, cb);
        }
    };
    return &funcs;
}
} // namespace EtsEnv
} // namespace OHOS

ETS_EXPORT extern "C" ETSEnvFuncs *OHOS_ETS_ENV_RegisterFuncs()
{
    return OHOS::EtsEnv::ETSEnvironment::RegisterFuncs();
}