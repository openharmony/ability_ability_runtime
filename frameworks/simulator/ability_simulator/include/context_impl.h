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

#ifndef OHOS_ABILITY_RUNTIME_SIMULATOR_CONTEXT_IMPL_H
#define OHOS_ABILITY_RUNTIME_SIMULATOR_CONTEXT_IMPL_H

#include "context.h"
#include "context_impl.h"
#include "resource_manager.h"
#include "simulator.h"
#include "uv.h"

namespace OHOS {
namespace AppExecFwk {
struct BundleInfo;
class BundleMgrHelper;
class OverlayEventSubscriber;
class Configuration;
} // namespace AppExecFwk
namespace AbilityRuntime {
class ContextImpl : public Context {
public:
    ContextImpl() = default;
    virtual ~ContextImpl() = default;

    std::shared_ptr<AppExecFwk::Configuration> GetConfiguration() override;
    void SetConfiguration(const std::shared_ptr<AppExecFwk::Configuration> &configuration);
    std::shared_ptr<AppExecFwk::ApplicationInfo> GetApplicationInfo() const override;
    void SetApplicationInfo(const std::shared_ptr<AppExecFwk::ApplicationInfo> &info);
    std::shared_ptr<Global::Resource::ResourceManager> GetResourceManager() const override;
    void SetResourceManager(const std::shared_ptr<Global::Resource::ResourceManager> &resourceManager);
    std::shared_ptr<AppExecFwk::HapModuleInfo> GetHapModuleInfo() const override;
    void InitHapModuleInfo(const AppExecFwk::HapModuleInfo &hapModuleInfo);

    std::shared_ptr<Context> CreateModuleContext(const std::string &moduleName) override;
    std::shared_ptr<Context> CreateModuleContext(const std::string &bundleName, const std::string &moduleName) override;
    std::shared_ptr<Context> CreateModuleContext(const std::string &moduleName, std::shared_ptr<Context> inputContext);
    std::shared_ptr<Context> CreateModuleContext(
        const std::string &bundleName, const std::string &moduleName, std::shared_ptr<Context> inputContext);

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
    static void FsReqCleanup(uv_fs_t *req);

private:
    static const int64_t CONTEXT_CREATE_BY_SYSTEM_APP;
    static const int EL_DEFAULT = 1;
    Options options_;
    std::string currArea_ = "el2";
    std::string fileSeparator_ = "/";
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager_ = nullptr;
    std::shared_ptr<AppExecFwk::Configuration> configuration_;
    std::shared_ptr<AppExecFwk::ApplicationInfo> applicationInfo_;
    std::shared_ptr<AppExecFwk::HapModuleInfo> hapModuleInfo_;
    bool Access(const std::string &path);
    void Mkdir(const std::string &path);
    bool CreateMultiDir(const std::string &path);
    void GetBundleInfo(
        const std::string &bundleName, const std::string &moduleName, AppExecFwk::BundleInfo &bundleInfo);
    void InitResourceManager(const AppExecFwk::BundleInfo &bundleInfo, const std::shared_ptr<ContextImpl> &appContext,
        bool currentBundle = false, const std::string &moduleName = "",
        std::shared_ptr<Context> inputContext = nullptr);
    std::shared_ptr<Global::Resource::ResourceManager> InitOthersResourceManagerInner(
        const AppExecFwk::BundleInfo &bundleInfo, bool currentBundle, const std::string &moduleName);
    std::shared_ptr<Global::Resource::ResourceManager> InitResourceManagerInner(
        const AppExecFwk::BundleInfo &bundleInfo, bool currentBundle, const std::string &moduleName,
        std::shared_ptr<Context> inputContext = nullptr);
    void UpdateResConfig(std::shared_ptr<Global::Resource::ResourceManager> &resourceManager);
    void UpdateResConfig(std::shared_ptr<Global::Resource::ResourceManager> src,
        std::shared_ptr<Global::Resource::ResourceManager> &resourceManager);
    std::string GetBundleNameWithContext(std::shared_ptr<Context> inputContext = nullptr) const;
    std::string GetPreviewPath();
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_SIMULATOR_CONTEXT_IMPL_H
