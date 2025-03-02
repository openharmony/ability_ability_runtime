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

#ifndef OHOS_ABILITY_RUNTIME_STS_UI_EXTENSION_CONTENT_SESSION_H
#define OHOS_ABILITY_RUNTIME_STS_UI_EXTENSION_CONTENT_SESSION_H

#include "session_info.h"
#include "start_options.h"
#include "window.h"
#include "sts_runtime.h"

namespace OHOS {
namespace AbilityRuntime {
using RuntimeTask = std::function<void(int, const AAFwk::Want&, bool)>;

class AbilityResultListener {
public:
    AbilityResultListener() = default;
    virtual ~AbilityResultListener() = default;
    virtual void OnAbilityResult(int requestCode, int resultCode, const AAFwk::Want &resultData) = 0;
    virtual bool IsMatch(int requestCode) = 0;
};

class AbilityResultListeners {
public:
    AbilityResultListeners() = default;
    virtual ~AbilityResultListeners() = default;
    void AddListener(const uint64_t &uiExtensionComponentId, std::shared_ptr<AbilityResultListener> listener) {}
    void RemoveListener(const uint64_t &uiExtensionComponentId) {}
    void OnAbilityResult(int requestCode, int resultCode, const AAFwk::Want &resultData) {}
private:
    std::map<uint64_t, std::shared_ptr<AbilityResultListener>> listeners_;
};

class UISessionAbilityResultListener : public AbilityResultListener {
public:
    UISessionAbilityResultListener() = default;
    virtual ~UISessionAbilityResultListener() = default;
    virtual void OnAbilityResult(int requestCode, int resultCode, const AAFwk::Want &resultData) {}
    virtual bool IsMatch(int requestCode) {return true;}
    void OnAbilityResultInner(int requestCode, int resultCode, const AAFwk::Want &resultData) {}
    void SaveResultCallbacks(int requestCode, RuntimeTask&& task) {}
private:
    std::map<int, RuntimeTask> resultCallbacks_;
};

class StsUIExtensionContentSession {
private:
    class CallbackWrapper;
public:
    StsUIExtensionContentSession(sptr<AAFwk::SessionInfo> sessionInfo,
        sptr<Rosen::Window> uiWindow, std::weak_ptr<AbilityRuntime::Context>& context,
        std::shared_ptr<AbilityResultListeners>& abilityResultListeners);
    StsUIExtensionContentSession(sptr<AAFwk::SessionInfo> sessionInfo,
        sptr<Rosen::Window> uiWindow);
    virtual ~StsUIExtensionContentSession() = default;
    static ani_object CreateStsUIExtensionContentSession(ani_env* env,
        sptr<AAFwk::SessionInfo> sessionInfo, sptr<Rosen::Window> uiWindow,
        std::weak_ptr<AbilityRuntime::Context> context,
        std::shared_ptr<AbilityResultListeners>& abilityResultListeners);

    void SendData(ani_env* env, ani_object object);
    void LoadContent(ani_env* env, ani_object object, ani_string path, ani_object storage);
    void TerminateSelf();
    void SetWindowBackgroundColor(std::string color);
    ani_object GetUIExtensionHostWindowProxy(ani_env* env, ani_object object);
    ani_object SetReceiveDataCallback(ani_env* env, ani_object object);
private:
    sptr<AAFwk::SessionInfo> sessionInfo_;
    sptr<Rosen::Window> uiWindow_;
    std::weak_ptr<AbilityRuntime::Context> context_;
    std::shared_ptr<CallbackWrapper> receiveDataCallback_;
    bool isRegistered = false;
    std::shared_ptr<CallbackWrapper> receiveDataForResultCallback_;
    bool isSyncRegistered = false;
    std::shared_ptr<UISessionAbilityResultListener> listener_;
    //sptr<JsFreeInstallObserver> freeInstallObserver_ = nullptr;
    bool isFirstTriggerBindModal_ = true;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_STS_UI_EXTENSION_CONTENT_SESSION_H
