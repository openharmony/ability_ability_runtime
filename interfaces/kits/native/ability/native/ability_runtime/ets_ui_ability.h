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

#ifndef OHOS_ABILITY_RUNTIME_ETS_UI_ABILITY_H
#define OHOS_ABILITY_RUNTIME_ETS_UI_ABILITY_H

#include "ui_ability.h"

#include "ability_delegator_infos.h"
#include "ets_native_reference.h"
#include "ets_runtime.h"

namespace OHOS {
namespace AbilityRuntime {
using AbilityHandler = AppExecFwk::AbilityHandler;
using AbilityInfo = AppExecFwk::AbilityInfo;
using OHOSApplication = AppExecFwk::OHOSApplication;
using Want = AppExecFwk::Want;

class EtsUIAbility : public UIAbility {
public:
    /**
     * @brief Create a EtsUIAbility instance through the singleton pattern
     * @param runtime The runtime of the ability
     * @return Returns the EtsUIability Instance point
     */
    static UIAbility *Create(const std::unique_ptr<Runtime> &runtime);

    explicit EtsUIAbility(ETSRuntime &etsRuntime);
    ~EtsUIAbility() override;

    /**
     * @brief Init the UIability
     * @param abilityInfo Indicate the Ability information
     * @param application Indicates the main process
     * @param handler the UIability EventHandler object
     * @param token the remote token
     */
    void Init(std::shared_ptr<AppExecFwk::AbilityLocalRecord> record,
        const std::shared_ptr<OHOSApplication> application,
        std::shared_ptr<AbilityHandler> &handler, const sptr<IRemoteObject> &token) override;

    /**
     * @brief OnStart,Start EtssUIability
     * @param want Indicates the {@link Want} structure containing startup information about the ability
     * @param sessionInfo Indicates the sessionInfo
     */
    void OnStart(const Want &want, sptr<AAFwk::SessionInfo> sessionInfo = nullptr) override;

    /**
     * @brief Called when this ability enters the <b>STATE_STOP</b> state.
     * The ability in the <b>STATE_STOP</b> is being destroyed.
     * You can override this function to implement your own processing logic.
     */
    void OnStop() override;

    /**
     * @brief Called when this ability enters the <b>STATE_STOP</b> state.
     * The ability in the <b>STATE_STOP</b> is being destroyed.
     * You can override this function to implement your own processing logic.
     * @param callbackInfo Indicates the lifecycle transaction callback information
     * @param isAsyncCallback Indicates whether it is an asynchronous lifecycle callback
     */
    void OnStop(AppExecFwk::AbilityTransactionCallbackInfo<> *callbackInfo, bool &isAsyncCallback) override;

    /**
     * @brief The callback of OnStop.
     */
    void OnStopCallback() override;

    /**
     * @brief Called when the launch mode of an ability is set to singleInstance. This happens when you re-launch an
     * ability that has been at the top of the ability stack.
     * @param want Indicates the new Want containing information about the ability.
     */
    void OnNewWant(const Want &want) override;

    /**
     * @brief Called when startAbilityForResult(ohos.aafwk.content.Want,int) is called to start an ability and the
     * result is returned. This method is called only on Page abilities. You can start a new ability to perform some
     * calculations and use setResult (int,ohos.aafwk.content.Want) to return the calculation result. Then the system
     * calls back the current method to use the returned data to execute its own logic.
     * @param requestCode Indicates the request code returned after the ability is started. You can define the request
     * code to identify the results returned by abilities. The value ranges from 0 to 65535.
     * @param resultCode Indicates the result code returned after the ability is started. You can define the result code
     * to identify an error.
     * @param want Indicates the data returned after the ability is started. You can define the data returned. The
     * value can be null.
     */
    void OnAbilityResult(int requestCode, int resultCode, const Want &resultData) override;

#ifdef SUPPORT_SCREEN
public:
    /**
     * @brief Called after instantiating WindowScene.
     * You can override this function to implement your own processing logic.
     */
    void OnSceneCreated() override;

    /**
     * @brief Called after ability stoped.
     * You can override this function to implement your own processing logic.
     */
    void onSceneDestroyed() override;

    /**
     * @brief Called when this ability enters the <b>STATE_FOREGROUND</b> state.
     * The ability in the <b>STATE_FOREGROUND</b> state is visible.
     * You can override this function to implement your own processing logic.
     */
    void OnForeground(const Want &want) override;

    /**
     * @brief Call "onForeground" ets function barely.
     *
     * @param want Want
     */
    void CallOnForegroundFunc(const Want &want) override;

    /**
     * @brief Called when this ability enters the <b>STATE_BACKGROUND</b> state.
     * The ability in the <b>STATE_BACKGROUND</b> state is invisible.
     * You can override this function to implement your own processing logic.
     */
    void OnBackground() override;

protected:
    void DoOnForeground(const Want &want) override;
    void ContinuationRestore(const Want &want) override;

private:
    bool IsRestorePageStack(const Want &want);
    void RestorePageStack(const Want &want);
    void GetPageStackFromWant(const Want &want, std::string &pageStack);
    void AbilityContinuationOrRecover(const Want &want);
    void UpdateEtsWindowStage(ani_ref windowStage);
    
    std::shared_ptr<AppExecFwk::ETSNativeReference> etsWindowStageObj_;
    int32_t windowMode_ = 0;
#endif

private:
    bool CallObjectMethod(bool withResult, const char *name, const char *signature, ...);
    ani_object CreateAppWindowStage();
    void SetAbilityContext(std::shared_ptr<AbilityInfo> abilityInfo, std::shared_ptr<Want> want,
        const std::string &moduleName, const std::string &srcPath, const std::shared_ptr<OHOSApplication> &application);
    void DoOnForegroundForSceneIsNull(const Want &want);
    void UpdateAbilityObj(std::shared_ptr<AbilityInfo> abilityInfo,
        const std::string &moduleName, const std::string &srcPath);
    void CreateEtsContext(int32_t screenMode, const std::shared_ptr<OHOSApplication> &application);
    bool BindNativeMethods();

    ETSRuntime &etsRuntime_;
    std::shared_ptr<AppExecFwk::ETSNativeReference> shellContextRef_;
    std::shared_ptr<AppExecFwk::ETSNativeReference> etsAbilityObj_;
    static std::once_flag singletonFlag_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_UI_ABILITY_H