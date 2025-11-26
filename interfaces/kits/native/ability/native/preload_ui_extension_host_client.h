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

#ifndef OHOS_ABILITY_RUNTIME_PRELOAD_UI_EXTENSION_HOST_CLIENT_H
#define OHOS_ABILITY_RUNTIME_PRELOAD_UI_EXTENSION_HOST_CLIENT_H

#include <map>
#include <memory>
#include <mutex>

#include "preload_ui_extension_callback_interface.h"
#include "preload_ui_extension_execute_callback_stub.h"
#include "want.h"

namespace OHOS {
namespace AbilityRuntime {
using PreloadTask = std::function<void(int32_t, int32_t)>;
using Want = AAFwk::Want;
struct PreloadByCallData {
    PreloadByCallData(PreloadTask &&callTask) : task(std::move(callTask))
    {
        handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    }
    PreloadByCallData(const PreloadByCallData &) = delete;
    PreloadByCallData &operator=(const PreloadByCallData &) = delete;

    PreloadTask task;
    std::mutex mutexlock;
    std::condition_variable condition;
    std::shared_ptr<AppExecFwk::EventHandler> handler_;
};

class PreloadUIExtensionHostClient : public AAFwk::PreloadUIExtensionExecuteCallbackStub {
public:
    PreloadUIExtensionHostClient() = default;
    virtual ~PreloadUIExtensionHostClient() = default;

    static sptr<PreloadUIExtensionHostClient> GetInstance();
    int32_t AddLoadedCallback(const std::shared_ptr<PreloadUIExtensionCallbackInterface> &callback);
    int32_t AddDestroyCallback(const std::shared_ptr<PreloadUIExtensionCallbackInterface> &callback);
    int32_t RemoveLoadedCallback(int32_t key);
    int32_t RemoveDestroyCallback(int32_t key);
    void RemoveAllLoadedCallback();
    void RemoveAllDestroyCallback();
    void PreloadUIExtensionAbility(const Want &want, std::string &hostBundleName, PreloadTask &&task);
    int32_t GenerateRequestCode();
    void OnLoadedDone(int32_t extensionAbilityId) override;
    void OnDestroyDone(int32_t extensionAbilityId) override;
    void OnPreloadSuccess(int32_t requestCode, int32_t extensionAbilityId, int32_t innerErrCode) override;

private:
    void RegisterPreloadUIExtensionHostClient();
    void UnRegisterPreloadUIExtensionHostClient();

    static std::mutex instanceMutex_;
    static std::once_flag singletonFlag_;
    bool isRegistered_ = false;
    std::atomic<int32_t> key_ = 0;
    static sptr<PreloadUIExtensionHostClient> instance_;
    mutable std::mutex preloadUIExtensionLoadedCallbackMutex_;
    mutable std::mutex preloadUIExtensionDestroyCallbackMutex_;
    mutable std::mutex registrationMutex_;
    mutable std::mutex requestCodeMutex_;
    std::atomic<int32_t> requestCode_ = 0;
    std::map<int, std::shared_ptr<PreloadByCallData>> resultCallbacks_;

    std::map<int32_t, std::shared_ptr<PreloadUIExtensionCallbackInterface>> loadedCallbackMap_;
    std::map<int32_t, std::shared_ptr<PreloadUIExtensionCallbackInterface>> destroyCallbackMap_;
    PreloadTask resultPreloadId;
    DISALLOW_COPY_AND_MOVE(PreloadUIExtensionHostClient);
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_PRELOAD_UI_EXTENSION_HOST_CLIENT_H