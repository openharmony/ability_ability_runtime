/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_JS_ABILITY_H
#define OHOS_ABILITY_RUNTIME_JS_ABILITY_H

#include "ability.h"
#include "ability_delegator_infos.h"
#include "freeze_util.h"

class NativeReference;

namespace OHOS {
namespace AbilityRuntime {
class JsRuntime;

using Ability = AppExecFwk::Ability;
using AbilityHandler = AppExecFwk::AbilityHandler;
using AbilityInfo = AppExecFwk::AbilityInfo;
using OHOSApplication = AppExecFwk::OHOSApplication;
using Want = AppExecFwk::Want;
using AbilityStartSetting = AppExecFwk::AbilityStartSetting;
using Configuration = AppExecFwk::Configuration;

class JsAbility : public Ability {
public:
    /**
     * @brief Create a JsAbility instance through the singleton pattern
     * @param runtime The runtime of the ability
     * @return Returns the JsAbility instance pointer
     */
    static Ability *Create(const std::unique_ptr<Runtime> &runtime);

    explicit JsAbility(JsRuntime &jsRuntime);
    ~JsAbility() override;

    /**
     * @brief Init the ability
     * @param abilityInfo Indicate the Ability information
     * @param application Indicates the main process
     * @param handler the ability EventHandler object
     * @param token the remote token
     */
    void Init(const std::shared_ptr<AbilityInfo> &abilityInfo, const std::shared_ptr<OHOSApplication> application,
        std::shared_ptr<AbilityHandler> &handler, const sptr<IRemoteObject> &token) override;

    /**
     * @brief OnStart, Start JsAbility
     * @param want Indicates the want containing startup information about the ability
     * @param sessionInfo Indicates the sessionInfo
     */
    void OnStart(const Want &want, sptr<AAFwk::SessionInfo> sessionInfo = nullptr) override;

    /**
     * @brief OnStop, Stop JsAbility
     */
    void OnStop() override;

    /**
     * @brief OnStop, Stop JsAbility
     * @param callbackInfo Indicates the lifecycle transaction callback information
     * @param isAsyncCallback Indicates whether it is an asynchronous lifecycle callback
     */
    void OnStop(AppExecFwk::AbilityTransactionCallbackInfo<> *callbackInfo, bool &isAsyncCallback) override;

    /**
     * @brief The callback of OnStop.
     */
    void OnStopCallback() override;

    /**
     * @brief Prepare user data of local Ability.
     * @param wantParams Indicates the user data to be saved.
     * @return If the ability is willing to continue and data saved successfully, it returns 0;
     * otherwise, it returns errcode.
     */
    int32_t OnContinue(WantParams &wantParams) override;

    /**
     * @brief Update configuration
     * @param configuration Indicates the updated configuration information.
     */
    void OnConfigurationUpdated(const Configuration &configuration) override;

    /**
     * @brief Update Context configuration
     */
    void UpdateContextConfiguration() override;

    /**
     * @brief Called when the system configuration is updated.
     * @param level Indicates the memory trim level, which shows the current memory usage status.
     */
    void OnMemoryLevel(int level) override;

    /**
     * @brief Called when you re-launch an ability that has been background state.
     * @param want Indicates the new Want containing information about the ability.
     */
    void OnNewWant(const Want &want) override;

    /**
     * @brief Prepare user data of local Ability.
     * @param reason the reason why framework invoke this function
     * @param wantParams Indicates the user data to be saved.
     * @return result code defined in abilityConstants
     */
    int32_t OnSaveState(int32_t reason, WantParams &wantParams) override;

    /**
     * @brief Called when the result is returned. This method is called only on Page abilities.
     * @param requestCode Indicates the request code returned after the ability is started.
     * @param resultCode Indicates the result code returned after the ability is started.
     * @param resultData Indicates the data returned after the ability is started.
     */
    void OnAbilityResult(int requestCode, int resultCode, const Want &resultData) override;

    /**
     * @brief Request a remote object of callee from this ability.
     * @return Returns the remote object of callee.
     */
    sptr<IRemoteObject> CallRequest() override;

    /**
     * @brief Dump ability info
     *
     * @param params dump params that indicate different dump targets
     * @param info dump ability info
     */
    virtual void Dump(const std::vector<std::string> &params, std::vector<std::string> &info) override;

    /**
     * @brief Get JsAbility
     * @return Return the JsAbility
     */
    std::shared_ptr<NativeReference> GetJsAbility();

    /**
     * @brief Callback when the ability is shared.
     * @param wantParams Indicates the user data to be saved.
     * @return the result of OnShare
     */
    int32_t OnShare(WantParams &wantParams) override;

#ifdef SUPPORT_SCREEN
public:
    /**
     * @brief Called after instantiating WindowScene.
     */
    void OnSceneCreated() override;

    /**
     * @brief Called after ability stopped.
     */
    void onSceneDestroyed() override;

    /**
     * @brief Called after ability restored.
     */
    void OnSceneRestored() override;

    /**
     * @brief Called when this ability enters the foreground state.
     */
    void OnForeground(const Want &want) override;

    /**
     * @brief Called when this ability enters the background state.
     */
    void OnBackground() override;

    /**
     * @brief Called when back press is dispatched.
     * Return true if ability will be moved to background; return false if will be terminated
     */
    bool OnBackPress() override;

    /**
     * @brief Called when ability prepare terminate.
     * @return Returns true if prepare terminate successfully.
     */
    bool OnPrepareTerminate() override;

    /**
     * @brief Get JsWindow Stage
     * @return Returns the current NativeReference
     */
    std::shared_ptr<NativeReference> GetJsWindowStage();

    /**
     * @brief Get JsRuntime
     * @return Returns the current JsRuntime
     */
    const JsRuntime& GetJsRuntime();

protected:
    /**
     * @brief Called when this ability enters the foreground state.
     * @param want Indicates the Want containing startup information about the ability
     */
    void DoOnForeground(const Want &want) override;

    /**
     * @brief Request focus for current window, can be override.
     * @param want Want
     */
    void RequestFocus(const Want &want) override;

    /**
     * @brief Called when ability continuation restore.
     * @param want Want
     */
    void ContinuationRestore(const Want &want) override;

private:
    /**
     * @brief Check if restore page stack.
     * @param want Want
     * @return Returns true if need restore page stack.
     */
    bool IsRestorePageStack(const Want &want);

    /**
     * @brief Restore page stack from want.
     * @param want Want
     */
    void RestorePageStack(const Want &want);

    /**
     * @brief Get page stack from want.
     * @param want Want
     * @param pageStack Page stack string
     */
    void GetPageStackFromWant(const Want &want, std::string &pageStack);

    /**
     * @brief Ability continuation or recover.
     * @param want Want
     */
    void AbilityContinuationOrRecover(const Want &want);
    std::shared_ptr<NativeReference> jsWindowStageObj_;
#endif

private:
    /**
     * @brief Call object method.
     * @param name The method name.
     * @param argv The arguments array.
     * @param argc The arguments count.
     * @param withResult Indicates whether return result.
     * @return Returns the result.
     */
    napi_value CallObjectMethod(const char *name, napi_value const *argv = nullptr, size_t argc = 0,
        bool withResult = false);

    /**
     * @brief Check if the result is a promise.
     * @param result The napi_value result.
     * @return Returns true if result is a promise.
     */
    bool CheckPromise(napi_value result);

    /**
     * @brief Call promise for lifecycle callback.
     * @param result The napi_value result.
     * @param callbackInfo The lifecycle transaction callback information.
     * @return Returns true if call promise successfully.
     */
    bool CallPromise(napi_value result, AppExecFwk::AbilityTransactionCallbackInfo<> *callbackInfo);

    /**
     * @brief Create application window stage.
     * @return Returns the NativeReference of window stage.
     */
    std::unique_ptr<NativeReference> CreateAppWindowStage();

    /**
     * @brief Create ability delegator property.
     * @return Returns the ADelegatorAbilityProperty shared pointer.
     */
    std::shared_ptr<AppExecFwk::ADelegatorAbilityProperty> CreateADelegatorAbilityProperty();

    /**
     * @brief Set new rule flag to callee.
     * @param env The napi environment.
     * @param remoteJsObj The remote object.
     * @return Returns the remote object.
     */
    sptr<IRemoteObject> SetNewRuleFlagToCallee(napi_env env, napi_value remoteJsObj);

    /**
     * @brief Add lifecycle event before call.
     * @param state The timeout state.
     * @param methodName The method name.
     */
    void AddLifecycleEventBeforeJSCall(FreezeUtil::TimeoutState state, const std::string &methodName) const;

    /**
     * @brief Add lifecycle event after call.
     * @param state The timeout state.
     * @param methodName The method name.
     */
    void AddLifecycleEventAfterJSCall(FreezeUtil::TimeoutState state, const std::string &methodName) const;

    /**
     * @brief Generate source path from ability info.
     * @param abilityInfo The ability information.
     * @return Returns the source path string.
     */
    std::string GenerateSrcPath(std::shared_ptr<AbilityInfo> abilityInfo) const;

    /**
     * @brief Bind ability context.
     */
    void BindContext();

    /**
     * @brief Initialize window scene.
     * @param want The want information.
     * @return Returns true if initialize successfully.
     */
    bool InitWindowScene(const Want &want);

    /**
     * @brief Add dump info from JavaScript dump method.
     * @param env The napi environment.
     * @param obj The object containing dump info.
     * @param params The dump params.
     * @param info The dump info vector to be filled.
     * @param methodName The method name.
     * @return Returns true if add dump info successfully.
     */
    bool AddDumpInfo(napi_env env, napi_value obj, const std::vector<std::string> &params,
        std::vector<std::string> &info, const std::string &methodName) const;

    JsRuntime &jsRuntime_;
    std::shared_ptr<NativeReference> shellContextRef_;
    std::shared_ptr<NativeReference> jsAbilityObj_;
    sptr<IRemoteObject> remoteCallee_;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_JS_ABILITY_H
