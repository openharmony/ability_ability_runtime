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

#ifndef OHOS_ABILITY_RUNTIME_STS_RUNTIME_H
#define OHOS_ABILITY_RUNTIME_STS_RUNTIME_H

#include <unordered_map>
#include <map>
#include <string>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "runtime.h"
#include "js_runtime.h"
#include "sts_envsetup.h"
#include "ani.h"

using AppLibPathMap = std::map<std::string, std::vector<std::string>>;
using AppLibPathVec = std::vector<std::string>;

namespace OHOS {
namespace StsEnv {
class STSEnvironment;
} // namespace StsEnv
struct STSUncaughtExceptionInfo;

namespace AbilityRuntime {

struct STSNativeReference
{
    ani_class     aniCls = nullptr;
    ani_object    aniObj = nullptr;
    ani_ref      aniRef = nullptr;
};

class STSRuntime : public Runtime {
public:
    static std::unique_ptr<STSRuntime> Create(const Options& options, Runtime* jsRuntime);
    static void SetAppLibPath(const AppLibPathMap& appLibPaths);
    ~STSRuntime() override;
    Language GetLanguage() const override
    {
        return Language::STS;
    }

    void StartDebugMode(const DebugOption debugOption) override;
    void DumpHeapSnapshot(bool isPrivate) override {}
    void NotifyApplicationState(bool isBackground) override {}
    // TODO uncompleted
    bool SuspendVM(uint32_t tid) override { return false; }
    // TODO uncompleted
    void ResumeVM(uint32_t tid) override {}
    void PreloadSystemModule(const std::string& moduleName) override {}
    void PreloadMainAbility(const std::string& moduleName, const std::string& srcPath,
        const std::string& hapPath,  bool isEsMode, const std::string& srcEntrance) override {}
    void PreloadModule(const std::string& moduleName, const std::string& srcPath,
        const std::string& hapPath, bool isEsMode, bool useCommonTrunk) override {}
    void FinishPreload() override {}
    bool LoadRepairPatch(const std::string& patchFile, const std::string& baseFile) override { return false; }
    bool NotifyHotReloadPage() override { return false; }
    bool UnLoadRepairPatch(const std::string& patchFile) override { return false; }
    void RegisterQuickFixQueryFunc(const std::map<std::string, std::string>& moduleAndPath) override {};
    void StartProfiler(const DebugOption debugOption) override {};
    // TODO uncompleted
    void SetModuleLoadChecker(const std::shared_ptr<ModuleCheckerDelegate> moduleCheckerDelegate) const override {}
    void SetDeviceDisconnectCallback(const std::function<bool()> &cb) override {};
    bool IsAppLibLoaded() const { return appLibLoaded_; }
    void UnLoadSTSAppLibrary();
    void DestroyHeapProfiler() override {};
    void ForceFullGC() override {};
    void ForceFullGC(uint32_t tid) override {};
    void DumpHeapSnapshot(uint32_t tid, bool isFullGC) override {};
    void DumpCpuProfile() override {};
    void AllowCrossThreadExecution() override {};
    void GetHeapPrepare() override {};
    void UpdatePkgContextInfoJson(std::string moduleName, std::string hapPath, std::string packageName) override {};
    void RegisterUncaughtExceptionHandler(void* uncaughtExceptionInfo) override;
    void PostTask(const std::function<void()>& task, const std::string& name, int64_t delayTime);
    void PostSyncTask(const std::function<void()>& task, const std::string& name);
    void RemoveTask(const std::string& name);
    ani_env* GetAniEnv();
    std::unique_ptr<STSNativeReference> LoadModule(const std::string& moduleName, const std::string& modulePath,
        const std::string& hapPath, bool esmodule, bool useCommonChunk, const std::string& srcEntrance);
    std::unique_ptr<STSNativeReference> LoadStsModule(const std::string& moduleName, const std::string& path, const std::string& hapPath,
        const std::string& srcEntrance);
    bool RunScript(ani_env* aniEnv, const std::string& moduleName, const std::string& abcPath,
        const std::string& hapPath, const std::string& srcEntrance);
private:
    bool StartDebugger();
    bool LoadSTSAppLibrary(const AppLibPathVec& appLibPaths);
    bool Initialize(const Options& options);
    void Deinitialize();
    bool CreateStsEnv(const Options& options);
    void PreloadAce(const Options& options);
    void ReInitStsEnvImpl(const Options& options);
    void PostPreload(const Options& options);
    void LoadAotFile(const Options& options);
    void ReInitUVLoop();
    void InitConsoleModule();
    void InitTimerModule();
    std::shared_ptr<StsEnv::STSEnvironment> stsEnv_;
    bool preloaded_ = false;
    // [cz] RunScript RunSandboxScript LoadModule PreloadMainAbility PreloadModule need
    int32_t apiTargetVersion_ = 0;
    // [cz] UpdateModuleNameAndAssetPath RunScript RunSandboxScript LoadModule PreloadMainAbility PreloadModule need
    bool isBundle_ = true;
    // [cz] RunSandboxScript LoadModule PreloadMainAbility PreloadModule need
    std::string codePath_;
    // [cz] UpdatePkgContextInfoJson need
    std::map<std::string, std::string> pkgContextInfoJsonStringMap_;
    std::map<std::string, std::string> packageNameList_;
    bool appLibLoaded_ = false;
    bool debugModel_ = false;
    std::string bundleName_;
    // uint32_t instanceId_ = 0;
    static AppLibPathVec appLibPaths_;
    std::string moduleName_;
    std::unordered_map<std::string, STSNativeReference*> modules_;

public:
    static AbilityRuntime::JsRuntime* jsRuntime_;
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_STS_RUNTIME_H
