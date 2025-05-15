/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_SIMULATOR_ABILITY_STAGE_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_SIMULATOR_ABILITY_STAGE_CONTEXT_H

#include "context.h"
#include "context_impl.h"
#include "simulator.h"
#include "uv.h"

namespace OHOS {
namespace AbilityRuntime {
class AbilityStageContext : public Context {
public:
    AbilityStageContext();
    virtual ~AbilityStageContext() = default;

    std::shared_ptr<AppExecFwk::Configuration> GetConfiguration() override;
    void SetConfiguration(const std::shared_ptr<AppExecFwk::Configuration> &configuration);
    std::shared_ptr<AppExecFwk::ApplicationInfo> GetApplicationInfo() const override;
    std::shared_ptr<AppExecFwk::HapModuleInfo> GetHapModuleInfo() const override;

    void SetApplicationInfo(const std::shared_ptr<AppExecFwk::ApplicationInfo> &info);
    void SetHapModuleInfo(const std::shared_ptr<AppExecFwk::HapModuleInfo> &info);

    void SetResourceManager(const std::shared_ptr<Global::Resource::ResourceManager> &resMgr);
    std::shared_ptr<Global::Resource::ResourceManager> GetResourceManager() const override;
    std::shared_ptr<Context> CreateModuleContext(const std::string &moduleName) override;
    std::shared_ptr<Context> CreateModuleContext(const std::string &bundleName, const std::string &moduleName) override;

    Options GetOptions() override;
    void SetOptions(const Options &options) override;
    std::string GetBundleName() const override;
    std::string GetBundleCodePath() override;
    std::string GetBundleCodeDir() override;
    std::string GetCacheDir() override;
    std::string GetTempDir() override;
    std::string GetResourceDir() override;
    std::string GetFilesDir() override;
    std::string GetDatabaseDir() override;
    std::string GetPreferencesDir() override;
    std::string GetDistributedFilesDir() override;
    std::string GetCloudFileDir() override;
    void SwitchArea(int mode) override;
    int GetArea() override;
    std::string GetBaseDir() override;
    std::string GetPreviewPath();
    static bool Access(const std::string &path);
    void Mkdir(const std::string &path);
    static void FsReqCleanup(uv_fs_t *req);
    bool CreateMultiDir(const std::string &path);
    using SelfType = AbilityStageContext;
    static const size_t CONTEXT_TYPE_ID;

protected:
    bool IsContext(size_t contextTypeId) override
    {
        return contextTypeId == CONTEXT_TYPE_ID || Context::IsContext(contextTypeId);
    }

private:
    static const int EL_DEFAULT = 1;
    Options options_;
    std::string currArea_ = "el2";
    std::string fileSeparator_ = "/";
    std::shared_ptr<AppExecFwk::HapModuleInfo> hapModuleInfo_;
    std::shared_ptr<ContextImpl> contextImpl_ = nullptr;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_SIMULATOR_ABILITY_STAGE_CONTEXT_H
