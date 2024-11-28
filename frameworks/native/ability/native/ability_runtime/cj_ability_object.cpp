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

#include "ability_runtime/cj_ability_object.h"

#include "cj_utils_ffi.h"
#include "hilog_tag_wrapper.h"
#include "want_params_wrapper.h"

using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;

using WantHandle = void*;

namespace {
// g_cjAbilityFuncs is used to save cj functions.
// It is assigned by the global variable REGISTER_ABILITY on the cj side which invokes RegisterCJAbilityFuncs.
// And it is never released.
CJAbilityFuncs* g_cjAbilityFuncs = nullptr;
} // namespace

void RegisterCJAbilityFuncs(void (*registerFunc)(CJAbilityFuncs*))
{
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    if (g_cjAbilityFuncs != nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "repeated registration for cj functions");
        return;
    }

    if (registerFunc == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null registerFunc");
        return;
    }

    g_cjAbilityFuncs = new CJAbilityFuncs();
    registerFunc(g_cjAbilityFuncs);
    TAG_LOGD(AAFwkTag::UIABILITY, "end");
}

namespace OHOS {
namespace AbilityRuntime {
std::shared_ptr<CJAbilityObject> CJAbilityObject::LoadModule(const std::string& name)
{
    if (g_cjAbilityFuncs == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null cjAbilityFunc");
        return nullptr;
    }
    auto id = g_cjAbilityFuncs->cjAbilityCreate(name.c_str());
    if (id == 0) {
        TAG_LOGE(AAFwkTag::UIABILITY,
            "failed to invoke , ability: %{public}s is not registered", name.c_str());
        return nullptr;
    }
    return std::make_shared<CJAbilityObject>(id);
}

CJAbilityObject::~CJAbilityObject()
{
    if (g_cjAbilityFuncs != nullptr) {
        g_cjAbilityFuncs->cjAbilityRelease(id_);
    }
    id_ = 0;
}

void CJAbilityObject::OnStart(const AAFwk::Want& want, const AAFwk::LaunchParam& launchParam) const
{
    if (g_cjAbilityFuncs == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null cjAbilityFunc");
        return;
    }
    WantHandle wantHandle = const_cast<AAFwk::Want*>(&want);
    CJLaunchParam param;
    param.launchReason = launchParam.launchReason;
    param.lastExitReason = launchParam.lastExitReason;
    param.lastExitMessage = CreateCStringFromString(launchParam.lastExitMessage);
    g_cjAbilityFuncs->cjAbilityOnStart(id_, wantHandle, param);
    free(param.lastExitMessage);
}

void CJAbilityObject::OnStop() const
{
    if (g_cjAbilityFuncs == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null cjAbilityFunc");
        return;
    }
    g_cjAbilityFuncs->cjAbilityOnStop(id_);
}

void CJAbilityObject::OnSceneCreated(OHOS::Rosen::CJWindowStageImpl* cjWindowStage) const
{
    if (g_cjAbilityFuncs == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null cjAbilityFunc");
        return;
    }
    WindowStagePtr windowStage = reinterpret_cast<WindowStagePtr>(cjWindowStage);
    g_cjAbilityFuncs->cjAbilityOnSceneCreated(id_, windowStage);
}

void CJAbilityObject::OnSceneRestored(OHOS::Rosen::CJWindowStageImpl* cjWindowStage) const
{
    if (g_cjAbilityFuncs == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null cjAbilityFunc");
        return;
    }
    WindowStagePtr windowStage = reinterpret_cast<WindowStagePtr>(cjWindowStage);
    g_cjAbilityFuncs->cjAbilityOnSceneRestored(id_, windowStage);
}

void CJAbilityObject::OnSceneWillDestroy(OHOS::Rosen::CJWindowStageImpl* cjWindowStage) const
{
    if (g_cjAbilityFuncs == nullptr || g_cjAbilityFuncs->cjAbilityOnSceneWillDestroy == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null cjAbilityFunc");
        return;
    }
    WindowStagePtr windowStage = reinterpret_cast<WindowStagePtr>(cjWindowStage);
    g_cjAbilityFuncs->cjAbilityOnSceneWillDestroy(id_, windowStage);
}

void CJAbilityObject::OnSceneDestroyed() const
{
    if (g_cjAbilityFuncs == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null cjAbilityFunc");
        return;
    }
    g_cjAbilityFuncs->cjAbilityOnSceneDestroyed(id_);
}

void CJAbilityObject::OnForeground(const Want& want) const
{
    if (g_cjAbilityFuncs == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null cjAbilityFunc");
        return;
    }
    WantHandle wantHandle = const_cast<AAFwk::Want*>(&want);
    g_cjAbilityFuncs->cjAbilityOnForeground(id_, wantHandle);
}

void CJAbilityObject::OnBackground() const
{
    if (g_cjAbilityFuncs == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null cjAbilityFunc");
        return;
    }
    g_cjAbilityFuncs->cjAbilityOnBackground(id_);
}

bool CJAbilityObject::OnBackPress(bool defaultRet) const
{
    if (g_cjAbilityFuncs == nullptr || g_cjAbilityFuncs->cjAbilityOnBackPress == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null cjAbilityFunc");
        return defaultRet;
    }
    return g_cjAbilityFuncs->cjAbilityOnBackPress(id_);
}

bool CJAbilityObject::OnPrepareTerminate() const
{
    if (g_cjAbilityFuncs == nullptr || g_cjAbilityFuncs->cjAbilityOnPrepareTerminate == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null cjAbilityFunc");
        return false;
    }
    return g_cjAbilityFuncs->cjAbilityOnPrepareTerminate(id_);
}

void CJAbilityObject::OnConfigurationUpdated(const std::shared_ptr<AppExecFwk::Configuration>& configuration) const
{
    if (g_cjAbilityFuncs == nullptr || g_cjAbilityFuncs->cjAbilityOnConfigurationUpdate == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null cjAbilityFunc");
        return;
    }
    auto cfg = CreateCConfiguration(*configuration);
    return g_cjAbilityFuncs->cjAbilityOnConfigurationUpdate(id_, cfg);
}

void CJAbilityObject::OnMemoryLevel(int32_t level) const
{
    if (g_cjAbilityFuncs == nullptr || g_cjAbilityFuncs->cjAbilityOnMemoryLevel == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null cjAbilityFunc");
        return;
    }
    g_cjAbilityFuncs->cjAbilityOnMemoryLevel(id_, level);
}

void CJAbilityObject::OnNewWant(const AAFwk::Want& want, const AAFwk::LaunchParam& launchParam) const
{
    if (g_cjAbilityFuncs == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null cjAbilityFunc");
        return;
    }
    WantHandle wantHandle = const_cast<AAFwk::Want*>(&want);
    CJLaunchParam param;
    param.launchReason = launchParam.launchReason;
    param.lastExitReason = launchParam.lastExitReason;
    param.lastExitMessage = CreateCStringFromString(launchParam.lastExitMessage);
    g_cjAbilityFuncs->cjAbilityOnNewWant(id_, wantHandle, param);
    free(param.lastExitMessage);
}

void CJAbilityObject::Dump(const std::vector<std::string>& params, std::vector<std::string>& info) const
{
    if (g_cjAbilityFuncs == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null cjAbilityFunc");
        return;
    }

    VectorStringHandle paramHandle = const_cast<std::vector<std::string>*>(&params);
    VectorStringHandle cjInfo = g_cjAbilityFuncs->cjAbilityDump(id_, paramHandle);
    if (cjInfo == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null cj info");
        return;
    }

    auto infoHandle = reinterpret_cast<std::vector<std::string>*>(cjInfo);
    for (std::string item : *infoHandle) {
        info.push_back(item);
    }
    // infoHandle is created in cj.
    delete infoHandle;
    infoHandle = nullptr;
}

int32_t CJAbilityObject::OnContinue(AAFwk::WantParams& wantParams) const
{
    if (g_cjAbilityFuncs == nullptr ||
        g_cjAbilityFuncs->cjAbilityOnContinueWithParams == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null cjAbilityFunc");
        return ContinuationManager::OnContinueResult::ON_CONTINUE_ERR;
    }
    auto params = CreateCStringFromString(OHOS::AAFwk::WantParamWrapper(wantParams).ToString());
    auto cjNumberParmas = g_cjAbilityFuncs->cjAbilityOnContinueWithParams(id_, params);
    auto returnParams = std::string(cjNumberParmas.params);
    free(params);
    free(cjNumberParmas.params);
    wantParams = OHOS::AAFwk::WantParamWrapper::ParseWantParamsWithBrackets(returnParams);
    return cjNumberParmas.numberResult;
}

int32_t CJAbilityObject::OnSaveState(int32_t reason, WantParams &wantParams) const
{
    if (g_cjAbilityFuncs == nullptr || g_cjAbilityFuncs->cjAbilityOnSaveState == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null cjAbilityFunc");
        return -1;
    }
    auto params = CreateCStringFromString(OHOS::AAFwk::WantParamWrapper(wantParams).ToString());
    auto cjNumberParmas = g_cjAbilityFuncs->cjAbilityOnSaveState(id_, reason, params);
    auto returnParams = std::string(cjNumberParmas.params);
    free(params);
    free(cjNumberParmas.params);
    wantParams = OHOS::AAFwk::WantParamWrapper::ParseWantParamsWithBrackets(returnParams);
    return cjNumberParmas.numberResult;
}

int32_t CJAbilityObject::OnShare(WantParams &wantParams) const
{
    if (g_cjAbilityFuncs == nullptr || g_cjAbilityFuncs->cjAbilityOnShare == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null cjAbilityFunc");
        return -1;
    }
    auto params = CreateCStringFromString(OHOS::AAFwk::WantParamWrapper(wantParams).ToString());
    auto cJReturnParams = g_cjAbilityFuncs->cjAbilityOnShare(id_, params);
    auto returnParams = std::string(cJReturnParams);
    free(params);
    free(cJReturnParams);
    wantParams = OHOS::AAFwk::WantParamWrapper::ParseWantParamsWithBrackets(returnParams);
    return ERR_OK;
}

void CJAbilityObject::Init(AbilityHandle ability) const
{
    if (g_cjAbilityFuncs == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null cjAbilityFunc");
        return;
    }
    g_cjAbilityFuncs->cjAbilityInit(id_, ability);
}

int64_t CJAbilityObject::GetId() const
{
    return id_;
}
} // namespace AbilityRuntime
} // namespace OHOS
