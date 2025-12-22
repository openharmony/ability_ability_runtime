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

#ifndef OHOS_ABILITY_RUNTIME_ETS_ENVIRONMENT_H
#define OHOS_ABILITY_RUNTIME_ETS_ENVIRONMENT_H

#include <functional>
#include <memory>
#include <string>
#include <uv.h>

#include "ets_exception_callback.h"
#include "ets_interface.h"
#include "ets_native_reference.h"
#include "event_handler.h"

#ifndef ETS_EXPORT
#ifndef __WINDOWS__
#define ETS_EXPORT __attribute__((visibility("default")))
#else
#define ETS_EXPORT __declspec(dllexport)
#endif
#endif

namespace OHOS {
namespace EtsEnv {
struct ETSRuntimeAPI {
    ani_status (*ANI_GetCreatedVMs)(ani_vm **vms_buffer, ani_size vms_buffer_length, ani_size *result);
    ani_status (*ANI_CreateVM)(const ani_options *options, uint32_t version, ani_vm **result);
};

using DebuggerPostTask = std::function<void(std::function<void()>&&)>;

class ETSEnvironment final : public std::enable_shared_from_this<ETSEnvironment> {
public:
    ETSEnvironment() {};

    static std::unique_ptr<ETSEnvironment> &GetInstance();
    static void InitETSSDKNS(const std::string &path);
    static void InitETSSysNS(const std::string &path);
    static ETSEnvFuncs *RegisterFuncs();

    bool Initialize(const std::shared_ptr<AppExecFwk::EventRunner> eventRunner, bool isDebug);
    void RegisterUncaughtExceptionHandler(const ETSUncaughtExceptionInfo &handle);
    ani_env *GetAniEnv();
    bool HandleUncaughtError();
    bool PreloadModule(const std::string &modulePath);
    bool LoadModule(const std::string &modulePath, const std::string &srcEntrance, void *&cls,
        void *&obj, void *&ref);
    bool FinishPreload();
    bool PostFork(void *napiEnv, const std::string &aotPath, const std::vector<std::string>& appInnerHspPathList,
        const std::vector<OHOS::AbilityRuntime::CommonHspBundleInfo> &commonHspBundleInfos,
        const std::shared_ptr<OHOS::AppExecFwk::EventRunner> &eventRunner);
    bool PreloadSystemClass(const char *className);

    void RemoveInstance(uint32_t instanceId);
    void StopDebugMode(void *jsVm);
    void StartDebuggerForSocketPair(std::string &option, int32_t socketFd);
    void NotifyDebugMode(uint32_t tid, uint32_t instanceId, bool isStartWithDebug, void *jsVm);
    void PostTask(const std::function<void()> &task, const std::string &name, int64_t delayTime);
    void BroadcastAndConnect(const std::string& bundleName, int socketFd);

    DebuggerPostTask GetDebuggerPostTask();

    struct VMEntry {
        ani_vm *aniVm_;
        ani_env *aniEnv_;
        VMEntry()
        {
            aniVm_ = nullptr;
            aniEnv_ = nullptr;
        }
    };

private:
    bool ConvertHspPathToAniArray(ani_env *aniEnv, const std::vector<std::string> &hapPathInfos,
        ani_array &refArray);
    std::vector<std::string> GetHspPathList();
    bool GetHspAbcRuntimeLinker(ani_array &refHspLinkerArray, ani_class cls);
    ani_object CreateRuntimeLinker(ani_env *aniEnv, ani_class cls, ani_ref undefined_ref, ani_array &refArray);
    bool LoadRuntimeApis();
    bool LoadSymbolCreateVM(void *handle, ETSRuntimeAPI &apis);
    bool LoadSymbolANIGetCreatedVMs(void *handle, ETSRuntimeAPI &apis);
    bool LoadBootPathFile(std::string &bootfiles);
    std::string GetBuildId(std::string stack);
    EtsEnv::ETSErrorObject GetETSErrorObject();
    std::string GetErrorProperty(ani_error aniError, const char *property);
    bool LoadAbcLinker(ani_env *env, const std::string &modulePath, ani_class &abcCls, ani_object &abcObj);
    void InitEventHandler(const std::shared_ptr<AppExecFwk::EventRunner> &eventRunner);
    int32_t ParseHdcRegisterOption(std::string& option);
    void PostCoroutineScheduleTask();
    static ETSRuntimeAPI lazyApis_;
    VMEntry vmEntry_;
    ETSUncaughtExceptionInfo uncaughtExceptionInfo_;
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler_;
    bool debugMode_ = false;
    std::vector<std::string> appInnerHspPathList_;
    std::vector<OHOS::AbilityRuntime::CommonHspBundleInfo> commonHspBundleInfos_;
};
} // namespace EtsEnv
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_ENVIRONMENT_H
