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

#ifndef OHOS_ABILITY_RUNTIME_STS_ENVIRONMENT_H
#define OHOS_ABILITY_RUNTIME_STS_ENVIRONMENT_H

#include <functional>
#include <memory>
#include <string>
#include <uv.h>

#include "event_handler.h"
#include "sts_environment_impl.h"
#include "sts_envsetup.h"
#include "sts_interface.h"
#include "ani.h"
#include "napi/native_api.h"

namespace OHOS {
struct STSRuntimeAPI;
using TaskFuncType = void (*)();
namespace StsEnv {
class StsEnvironmentImpl;
class STSEnvironment final {
public:
    explicit STSEnvironment(std::unique_ptr<StsEnvironmentImpl> impl);

    bool IsRuntimeStarted()
    {
        return isRuntimeStarted_;
    }

    static void InitSTSChipSDKNS(const std::string& path);
    static void InitSTSAppNS(const std::string& path);
    static void InitSTSSDKNS(const std::string& path);
    static void InitSTSSysNS(const std::string& path);
    bool StartRuntime(napi_env napiEnv, std::vector<ani_option>& options);
    void StopRuntime();
    void RegisterUncaughtExceptionHandler(const STSUncaughtExceptionInfo& handle);
    bool IsUISchedulerStarted()
    {
        return isUISchedulerStarted_;
    }
    bool StartUIScheduler();
    void StopUIScheduler();
    enum LibraryKind {
        SYSTEM,
        SDK,
        APP,
    };
    void* GetUIScheduler()
    {
        if (!isUISchedulerStarted_) {
            return nullptr;
        }
        return uiScheduler_;
    }

    void* LoadSTSLibrary(const char* dlName);
    void UnLoadSTSLibrary(void* handle);

    bool StartDebugger();
    bool PostTask(TaskFuncType task);
    void PostTask(const std::function<void()>& task, const std::string& name = "", int64_t delayTime = 0);
    void PostSyncTask(const std::function<void()>& task, const std::string& name);
    void RemoveTask(const std::string& name);
    bool InitLoop(bool isStage);
    void DeInitLoop();
    bool ReInitUVLoop();
    EtsVM* GetEtsVM();
    EtsEnv* GetEtsEnv();
    void ReInitStsEnvImpl(std::unique_ptr<StsEnvironmentImpl> impl);
    ani_env* GetAniEnv();
    void HandleUncaughtError();

    static const char* stsAppNSName;
    static const char* stsSDKNSName;
    static const char* stsSysNSName;
    static const char* stsChipSDKNSName;

    struct VMEntry {
        int vmKind;
        EtsVM* vm;
        EtsEnv* env;
        void* app;
        void* enter;
        void* emitEvent;
        ani_vm *ani_vm;
        ani_env *ani_env;
        VMEntry()
        {
            vmKind = 0;
            vm = nullptr;
            env = nullptr;
            app = nullptr;
            enter = nullptr;
            ani_vm = nullptr;
            ani_env = nullptr;
            emitEvent = nullptr;
        }
    };

private:
    bool LoadRuntimeApis();
    bool LoadSymbolGetDefaultVMInitArgs(void* handle, STSRuntimeAPI& apis);
    bool LoadSymbolGetCreatedVMs(void* handle, STSRuntimeAPI& apis);
    bool LoadSymbolCreateVM(void* handle, STSRuntimeAPI& apis);
    bool LoadSymbolANIGetCreatedVMs(void* handle, STSRuntimeAPI& apis);
    bool LoadBootPathFile(std::string& bootfiles);
    void Schedule();
    std::string GetBuildId(std::string stack);
    StsEnv::STSErrorObject GetSTSErrorObject();
    std::string GetErrorProperty(ani_error aniError, const char* property);
    static STSRuntimeAPI lazyApis_;
    bool isRuntimeStarted_{ false };
    bool isUISchedulerStarted_{ false };
    void* uiScheduler_{ nullptr };
    VMEntry vmEntry_;
    std::unique_ptr<StsEnvironmentImpl> impl_ = nullptr;
    STSUncaughtExceptionInfo uncaughtExceptionInfo_;
};
} // namespace StsEnv
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_STS_ENVIRONMENT_H
