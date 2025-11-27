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
#include <map>

#include "ohos.distributedmissionmanager.proj.hpp"
#include "ohos.distributedmissionmanager.impl.hpp"
#include "taihe/runtime.hpp"
#include "ability_manager_client.h"
#include "ani_common_want.h"
#include "ani_error_utils.h"
#include "ani_observer_utils.h"
#include "ani_remotelistener_utils.h"
#include "dms_continueInfo.h"
#include "dms_sa_client.h"
#include "hilog_tag_wrapper.h"
#include "mission_continue_interface.h"

namespace {
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

constexpr size_t VALUE_BUFFER_SIZE = 128;
constexpr const char* ON_CONTINUTESTATE_CHANGE = "continueStateChange";

std::mutex registrationLock_;
std::map<std::string, sptr<ani_remotelistenerutils::AniRemoteMissionListener>> registrationMap_;

std::recursive_mutex onLock_;
std::map<std::string, sptr<ani_observerutils::MissionObserver>> registrationOfOnMap_;

void OnContinueStateChange(ani_observerutils::JsOnCallbackViewType callback)
{
    std::lock_guard<std::recursive_mutex> lock(onLock_);
    sptr<ani_observerutils::MissionObserver> registrationOfOnItem;
    auto item = registrationOfOnMap_.find(ON_CONTINUTESTATE_CHANGE);
    if (item != registrationOfOnMap_.end()) {
        registrationOfOnItem = registrationOfOnMap_[ON_CONTINUTESTATE_CHANGE];
    } else {
        registrationOfOnItem = new (std::nothrow) ani_observerutils::MissionObserver();
    }
    bool addRet = registrationOfOnItem->AddCallback(callback);
    if (!addRet) {
        return;
    }

    int32_t result = DmsSaClient::GetInstance().AddListener(ON_CONTINUTESTATE_CHANGE, registrationOfOnItem);
    if (result == OHOS::AAFwk::NO_ERROR) {
        TAG_LOGI(AAFwkTag::MISSION, "DmsSaClient AddListener success");
        registrationOfOnMap_[ON_CONTINUTESTATE_CHANGE] = registrationOfOnItem;
    } else {
        TAG_LOGE(AAFwkTag::MISSION, "DmsSaClient AddListener failed, %{public}d", result);
        int32_t errCode = ani_errorutils::ErrorCodeReturn(result);
        std::string errInfo = ani_errorutils::ErrorMessageReturn(errCode);
        ani_errorutils::ThrowError(errCode, errInfo.c_str());
    }
}

void OffContinueStateChange(::taihe::optional_view<ani_observerutils::JsOnCallbackType> callbackOpt)
{
    std::lock_guard<std::recursive_mutex> autoLock(onLock_);
    sptr<ani_observerutils::MissionObserver> registrationOfOnItem;
    auto item = registrationOfOnMap_.find(ON_CONTINUTESTATE_CHANGE);
    if (item != registrationOfOnMap_.end()) {
        registrationOfOnItem = registrationOfOnMap_[ON_CONTINUTESTATE_CHANGE];
    } else {
        TAG_LOGI(AAFwkTag::MISSION, "ON_CONTINUTESTATE_CHANGE callback empty");
        return;
    }
    registrationOfOnItem->DeleteCallback(callbackOpt);

    if (!registrationOfOnItem->IsCallbackListEmpty()) {
        TAG_LOGI(AAFwkTag::MISSION, "callback not empty, return");
        return;
    }
    int32_t result = DmsSaClient::GetInstance().DelListener(ON_CONTINUTESTATE_CHANGE, registrationOfOnItem);
    if (result == OHOS::AAFwk::NO_ERROR) {
        TAG_LOGI(AAFwkTag::MISSION, "DmsSaClient DelListener success");
        registrationOfOnMap_.erase(ON_CONTINUTESTATE_CHANGE);
    } else {
        TAG_LOGE(AAFwkTag::MISSION, "DmsSaClient DelListener failed, %{public}d", result);
        int32_t errCode = ani_errorutils::ErrorCodeReturn(result);
        std::string errInfo = ani_errorutils::ErrorMessageReturn(errCode);
        ani_errorutils::ThrowError(errCode, errInfo.c_str());
    }
}

bool CheckDeviceIdValid(std::string deviceId)
{
    if (deviceId.length() > VALUE_BUFFER_SIZE) {
        TAG_LOGE(AAFwkTag::MISSION, "deviceId length not correct");
        std::string errInfo = "Parameter error. The length of \"deviceId\" must be less than " +
            std::to_string(VALUE_BUFFER_SIZE);
        ani_errorutils::ThrowError(ErrorCode::PARAMETER_CHECK_FAILED, errInfo.c_str());
        return false;
    }
    return true;
}

void StartSyncRemoteMissionsSync(::MissionParameter::MissionParameter const& parameter)
{
    std::string deviceId(parameter.deviceId);
    if (!CheckDeviceIdValid(deviceId)) {
        return;
    }

    int32_t result = AbilityManagerClient::GetInstance()->StartSyncRemoteMissions(deviceId,
        parameter.fixConflict, parameter.tag);
    if (result != 0) {
        TAG_LOGE(AAFwkTag::MISSION, "StartSyncRemoteMissions failed, %{public}d", result);
        int32_t errCode = ani_errorutils::ErrorCodeReturn(result);
        std::string errInfo = ani_errorutils::ErrorMessageReturn(errCode);
        ani_errorutils::ThrowError(errCode, errInfo.c_str());
    }
}

void StopSyncRemoteMissionsSync(::MissionDeviceInfo::MissionDeviceInfo const& parameter)
{
    std::string deviceId(parameter.deviceId);
    if (!CheckDeviceIdValid(deviceId)) {
        return;
    }

    int32_t result = AbilityManagerClient::GetInstance()->StopSyncRemoteMissions(deviceId);
    if (result != 0) {
        TAG_LOGE(AAFwkTag::MISSION, "StopSyncRemoteMissions failed, %{public}d", result);
        int32_t errCode = ani_errorutils::ErrorCodeReturn(result);
        std::string errInfo = ani_errorutils::ErrorMessageReturn(errCode);
        ani_errorutils::ThrowError(errCode, errInfo.c_str());
    }
}

void RegisterMissionListenerSync(::MissionDeviceInfo::MissionDeviceInfo const& parameter,
    ::MissionCallbacks::MissionCallback const& options)
{
    std::string deviceId(parameter.deviceId);
    if (!CheckDeviceIdValid(deviceId)) {
        return;
    }
    std::lock_guard<std::mutex> autoLock(registrationLock_);
    sptr<ani_remotelistenerutils::AniRemoteMissionListener> registration;
    auto item = registrationMap_.find(deviceId);
    if (item != registrationMap_.end()) {
        TAG_LOGI(AAFwkTag::MISSION, "registration exits");
        registration = registrationMap_[deviceId];
        registration->SetCallbacks(options);
    } else {
        TAG_LOGI(AAFwkTag::MISSION, "registration not exits");
        registration = new (std::nothrow) ani_remotelistenerutils::AniRemoteMissionListener(options);
    }
    if (registration == nullptr) {
        TAG_LOGE(AAFwkTag::MISSION, "null missionRegistration");
        int32_t errCode = ani_errorutils::ErrorCodeReturn(-1);
        std::string errInfo = ani_errorutils::ErrorMessageReturn(errCode);
        ani_errorutils::ThrowError(errCode, errInfo.c_str());
        return;
    }

    int32_t result = AbilityManagerClient::GetInstance()->RegisterMissionListener(deviceId, registration);
    if (result == OHOS::AAFwk::NO_ERROR) {
        TAG_LOGI(AAFwkTag::MISSION, "AbilityManagerClient RegisterMissionListener success");
        registrationMap_[deviceId] = registration;
    } else {
        TAG_LOGE(AAFwkTag::MISSION, "AbilityManagerClient RegisterMissionListener failed, %{public}d", result);
        int32_t errCode = ani_errorutils::ErrorCodeReturn(result);
        std::string errInfo = ani_errorutils::ErrorMessageReturn(errCode);
        ani_errorutils::ThrowError(errCode, errInfo.c_str());
    }
}

void UnRegisterMissionListenerSync(::MissionDeviceInfo::MissionDeviceInfo const& parameter)
{
    std::string deviceId(parameter.deviceId);
    if (!CheckDeviceIdValid(deviceId)) {
        return;
    }

    std::lock_guard<std::mutex> autoLock(registrationLock_);
    sptr<ani_remotelistenerutils::AniRemoteMissionListener> registration;
    auto item = registrationMap_.find(deviceId);
    if (item != registrationMap_.end()) {
        TAG_LOGI(AAFwkTag::MISSION, "registration exits");
        registration = registrationMap_[deviceId];
    } else {
        TAG_LOGI(AAFwkTag::MISSION, "registration not exits");
        int32_t errCode = ani_errorutils::ErrorCodeReturn(INVALID_PARAMETERS_ERR);
        std::string errInfo = ani_errorutils::ErrorMessageReturn(errCode);
        ani_errorutils::ThrowError(errCode, errInfo.c_str());
        return;
    }
    int32_t result = AbilityManagerClient::GetInstance()->UnRegisterMissionListener(deviceId, registration);
    if (result == OHOS::AAFwk::NO_ERROR) {
        TAG_LOGI(AAFwkTag::MISSION, "AbilityManagerClient UnRegisterMissionListener success");
        registration->Release();
        registrationMap_.erase(deviceId);
    } else {
        TAG_LOGE(AAFwkTag::MISSION, "AbilityManagerClient UnRegisterMissionListener failed, %{public}d", result);
        int32_t errCode = ani_errorutils::ErrorCodeReturn(result);
        std::string errInfo = ani_errorutils::ErrorMessageReturn(errCode);
        ani_errorutils::ThrowError(errCode, errInfo.c_str());
    }
}

OHOS::AAFwk::ContinueMissionInfo ParseContinueMissionInfoFromTaihe(ani_env* env,
    ::ContinueMissionInfo::ContinueMissionInfo const& parameter)
{
    TAG_LOGI(AAFwkTag::MISSION, "ParseContinueMissionInfoFromTaihe");
    OHOS::AAFwk::ContinueMissionInfo continueMissionInfo;
    continueMissionInfo.dstDeviceId = std::string(parameter.dstDeviceId);
    continueMissionInfo.srcDeviceId = std::string(parameter.srcDeviceId);
    continueMissionInfo.bundleName = std::string(parameter.bundleName);
    if (parameter.srcBundleName.has_value()) {
        continueMissionInfo.srcBundleName = std::string(parameter.srcBundleName.value());
    }
    if (parameter.continueType.has_value()) {
        continueMissionInfo.continueType = std::string(parameter.continueType.value());
    }
    UnwrapWantParams(env, reinterpret_cast<ani_ref>(parameter.wantParam), continueMissionInfo.wantParams);
    continueMissionInfo.wantParams.DumpInfo(0);
    return continueMissionInfo;
}

void ContinueMissionWithMissionInfoCallback(::ContinueMissionInfo::ContinueMissionInfo const& parameter,
    ::taihe::callback_view<void(uintptr_t err)> callback)
{
    TAG_LOGI(AAFwkTag::MISSION, "ContinueMissionWithMissionInfoCallbackSync");
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        ani_errorutils::ThrowError(SYSTEM_WORK_ABNORMALLY, "ani env is null");
        return;
    }
    OHOS::AAFwk::ContinueMissionInfo continueMissionInfo = ParseContinueMissionInfoFromTaihe(env, parameter);
    auto continuation = sptr<ani_remotelistenerutils::AniMissionContinue>::MakeSptr(callback);

    int32_t result = AAFwk::AbilityManagerClient::GetInstance()->ContinueMission(continueMissionInfo, continuation);
    TAG_LOGI(AAFwkTag::MISSION, "AbilityManagerClient ContinueMission return %{public}d", result);
    if (result != OHOS::AAFwk::NO_ERROR) {
        continuation->OnContinueDone(result);
    }
}

uintptr_t ContinueMissionWithMissionInfoPromise(::ContinueMissionInfo::ContinueMissionInfo const& parameter)
{
    TAG_LOGI(AAFwkTag::MISSION, "ContinueMissionWithMissionInfoPromiseSync");
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        ani_errorutils::ThrowError(SYSTEM_WORK_ABNORMALLY, "ani env is null");
        return 0;
    }
    ani_status status = ANI_OK;
    ani_object promise = nullptr;
    ani_resolver deferred = nullptr;
    if ((status = env->Promise_New(&deferred, &promise)) != ANI_OK) {
        TAG_LOGI(AAFwkTag::MISSION, "create promise object failed, status = %{public}d", status);
        ani_errorutils::ThrowError(SYSTEM_WORK_ABNORMALLY, "new promise failed");
        return 0;
    }
    OHOS::AAFwk::ContinueMissionInfo continueMissionInfo = ParseContinueMissionInfoFromTaihe(env, parameter);
    auto continuation = sptr<ani_remotelistenerutils::AniMissionContinue>::MakeSptr(env, deferred);
    int32_t result = AAFwk::AbilityManagerClient::GetInstance()->ContinueMission(continueMissionInfo, continuation);
    TAG_LOGI(AAFwkTag::MISSION, "AbilityManagerClient ContinueMission return %{public}d", result);
    if (result != OHOS::AAFwk::NO_ERROR) {
        continuation->OnContinueDone(result);
    }
    return reinterpret_cast<uintptr_t>(promise);
}

void ContinueMissionWithDeviceInfoSync(::ContinueDeviceInfo::ContinueDeviceInfo const& parameter,
    ::ContinueCallback::ContinueCallback const& options)
{
    TAG_LOGI(AAFwkTag::MISSION, "ContinueMissionWithDeviceInfoSync");
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        ani_errorutils::ThrowError(SYSTEM_WORK_ABNORMALLY, "ani env is null");
        return;
    }
    AAFwk::WantParams wantParams;
    OHOS::AAFwk::ContinueMissionInfo continueMissionInfo;
    continueMissionInfo.dstDeviceId = std::string(parameter.dstDeviceId);
    continueMissionInfo.srcDeviceId = std::string(parameter.srcDeviceId);
    UnwrapWantParams(env, reinterpret_cast<ani_ref>(parameter.wantParam), continueMissionInfo.wantParams);

    auto continuation = sptr<ani_remotelistenerutils::AniMissionContinue>::MakeSptr(options);
    int32_t result = AAFwk::AbilityManagerClient::GetInstance()->ContinueMission(
        continueMissionInfo.srcDeviceId, continueMissionInfo.dstDeviceId,
        parameter.missionId, continuation, continueMissionInfo.wantParams);
    TAG_LOGI(AAFwkTag::MISSION, "AbilityManagerClient ContinueMission return %{public}d", result);
    if (result != OHOS::AAFwk::NO_ERROR) {
        int32_t errCode = ani_errorutils::ErrorCodeReturn(result);
        std::string errInfo = ani_errorutils::ErrorMessageReturn(errCode);
        ani_errorutils::ThrowError(errCode, errInfo.c_str());
    }
}

}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_OnContinueStateChange(OnContinueStateChange);
TH_EXPORT_CPP_API_OffContinueStateChange(OffContinueStateChange);
TH_EXPORT_CPP_API_StartSyncRemoteMissionsSync(StartSyncRemoteMissionsSync);
TH_EXPORT_CPP_API_StopSyncRemoteMissionsSync(StopSyncRemoteMissionsSync);
TH_EXPORT_CPP_API_RegisterMissionListenerSync(RegisterMissionListenerSync);
TH_EXPORT_CPP_API_UnRegisterMissionListenerSync(UnRegisterMissionListenerSync);
TH_EXPORT_CPP_API_ContinueMissionWithMissionInfoCallback(ContinueMissionWithMissionInfoCallback);
TH_EXPORT_CPP_API_ContinueMissionWithMissionInfoPromise(ContinueMissionWithMissionInfoPromise);
TH_EXPORT_CPP_API_ContinueMissionWithDeviceInfoSync(ContinueMissionWithDeviceInfoSync);
// NOLINTEND
