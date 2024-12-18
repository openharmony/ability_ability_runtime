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

#include "hilog_tag_wrapper.h"
#include "want_agent_helper.h"
#include "want_params_wrapper.h"
#include "start_options.h"
#include "cj_want_agent_ffi.h"
#include "cj_ability_runtime_error.h"
#include "cj_utils_ffi.h"
#include "cj_lambda.h"

namespace OHOS {
namespace FfiWantAgent {

using namespace OHOS::AbilityRuntime;

constexpr int32_t BUSINESS_ERROR_CODE_OK = 0;
constexpr int32_t NOTEQ = -1;

CJTriggerCompleteCallBack::CJTriggerCompleteCallBack()
{}

CJTriggerCompleteCallBack::~CJTriggerCompleteCallBack()
{}

void CJTriggerCompleteCallBack::SetCallbackInfo(std::function<void(CJCompleteData)> callback)
{
    callback_ = callback;
}

void CJTriggerCompleteCallBack::SetWantAgentInstance(int64_t wantAgent)
{
    wantAgent_ = wantAgent;
}

void CJTriggerCompleteCallBack::OnSendFinished(
    const AAFwk::Want &want, int resultCode, const std::string &resultData, const AAFwk::WantParams &resultExtras)
{
    CJCompleteData data = { .info = wantAgent_, .want = new (std::nothrow) AAFwk::Want(want),
        .finalCode = resultCode, .finalData = CreateCStringFromString(resultData),
        .extraInfo = CreateCStringFromString(OHOS::AAFwk::WantParamWrapper(resultExtras).ToString())};
    callback_(data);
}

std::string CJWantAgent::OnGetBundleName(int32_t *errCode)
{
    std::string bundleName = "";
    *errCode = WantAgentHelper::GetBundleName(wantAgent_, bundleName);
    return bundleName;
}

int32_t CJWantAgent::OnGetUid(int32_t *errCode)
{
    int uid = -1;
    *errCode = WantAgentHelper::GetUid(wantAgent_, uid);
    return uid;
}

void CJWantAgent::OnCancel(int32_t *errCode)
{
    *errCode = WantAgentHelper::Cancel(wantAgent_);
}

void CJWantAgent::OnTrigger(CJTriggerInfo cjTriggerInfo, std::function<void(CJCompleteData)> callback, int32_t *errCode)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "called");
    std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent = nullptr;
    TriggerInfo triggerInfo;
    auto triggerObj = std::make_shared<CJTriggerCompleteCallBack>();
    *errCode = UnWrapTriggerInfoParam(cjTriggerInfo, callback, wantAgent, triggerInfo, triggerObj);
    if (*errCode != NO_ERROR) {
        return;
    }
    TAG_LOGD(AAFwkTag::WANTAGENT, "called");
    WantAgentHelper::TriggerWantAgent(wantAgent, triggerObj, triggerInfo);
}

int32_t CJWantAgent::UnWrapTriggerInfoParam(CJTriggerInfo cjTriggerInfo, std::function<void(CJCompleteData)> callback,
    std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> &wantAgent, TriggerInfo &triggerInfo,
    std::shared_ptr<CJTriggerCompleteCallBack> &triggerObj)
{
    wantAgent = wantAgent_;
    std::shared_ptr<AAFwk::Want> want = nullptr;
    if (cjTriggerInfo.hasWant) {
        auto actualWant = reinterpret_cast<AAFwk::Want*>(cjTriggerInfo.want);
        want = std::make_shared<AAFwk::Want>(*actualWant);
    }
    std::string permission = std::string(cjTriggerInfo.permission);
    std::shared_ptr<AAFwk::WantParams> extraInfo = nullptr;
    if (cjTriggerInfo.extraInfos != nullptr) {
        extraInfo = std::make_shared<AAFwk::WantParams>(
            OHOS::AAFwk::WantParamWrapper::ParseWantParamsWithBrackets(cjTriggerInfo.extraInfos));
    }
    std::shared_ptr<AAFwk::StartOptions> startOptions = std::make_shared<AAFwk::StartOptions>();
    
    TriggerInfo triggerInfoData(permission, extraInfo, want, startOptions, cjTriggerInfo.code);
    triggerInfo = triggerInfoData;
    if (triggerObj != nullptr) {
        triggerObj->SetCallbackInfo(callback);
        triggerObj->SetWantAgentInstance(GetID());
    }
    return BUSINESS_ERROR_CODE_OK;
}

int32_t CJWantAgent::OnGetOperationType(int32_t *errCode)
{
    int32_t operType;
    *errCode = WantAgentHelper::GetType(wantAgent_, operType);
    return operType;
}

bool CJWantAgent::OnEqual(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> second, int32_t *errCode)
{
    *errCode = WantAgentHelper::IsEquals(wantAgent_, second);
    if (*errCode == BUSINESS_ERROR_CODE_OK) {
        return true;
    } else if (*errCode == NOTEQ) {
        *errCode = BUSINESS_ERROR_CODE_OK;
    }
    return false;
}

extern "C" {
int64_t FfiWantAgentGetWantAgent(CJWantAgentInfo info, int32_t *errCode)
{
    std::shared_ptr<AAFwk::WantParams> extraInfo =
        std::make_shared<AAFwk::WantParams>(
            OHOS::AAFwk::WantParamWrapper::ParseWantParamsWithBrackets(info.extraInfos));
    std::vector<WantAgentConstant::Flags> wantAgentFlags;
    for (int64_t i = 0; i < info.actionFlags.size; i++) {
        wantAgentFlags.emplace_back(static_cast<WantAgentConstant::Flags>(info.actionFlags.head[i]));
    }
    std::vector<std::shared_ptr<AAFwk::Want>> wants;
    for (int64_t i = 0; i < info.wants.size; i++) {
        auto actualWant = reinterpret_cast<AAFwk::Want*>(info.wants.head[i]);
        wants.emplace_back(std::make_shared<AAFwk::Want>(*actualWant));
    }
    WantAgentInfo wantAgentInfo(info.requestCode,
                                static_cast<WantAgentConstant::OperationType>(info.actionType),
                                wantAgentFlags,
                                wants,
                                extraInfo);
    auto context = Context::GetApplicationContext();
    std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent = nullptr;
    ErrCode result = WantAgentHelper::GetWantAgent(context, wantAgentInfo, wantAgent);
    if (result != NO_ERROR) {
        *errCode = result;
        return -1;
    } else {
        if (wantAgent == nullptr) {
            *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
            return -1;
        }
        auto nativeWantAgent = OHOS::FFI::FFIData::Create<CJWantAgent>(
            std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgent>(wantAgent->GetPendingWant()));
        return nativeWantAgent->GetID();
    }
}

char* FfiWantAgentGetBoundleName(int64_t cjWantAgent, int32_t *errCode)
{
    auto nativeWantAgent = OHOS::FFI::FFIData::GetData<CJWantAgent>(cjWantAgent);
    if (nativeWantAgent == nullptr) {
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return nullptr;
    }
    std::string bundleName = nativeWantAgent->OnGetBundleName(errCode);
    if (*errCode != NO_ERROR) {
        return nullptr;
    }
    return CreateCStringFromString(bundleName);
}

int32_t FfiWantAgentGetUid(int64_t cjWantAgent, int32_t *errCode)
{
    auto nativeWantAgent = OHOS::FFI::FFIData::GetData<CJWantAgent>(cjWantAgent);
    if (nativeWantAgent == nullptr) {
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return -1;
    }
    return nativeWantAgent->OnGetUid(errCode);
}

void FfiWantAgentCancel(int64_t cjWantAgent, int32_t *errCode)
{
    auto nativeWantAgent = OHOS::FFI::FFIData::GetData<CJWantAgent>(cjWantAgent);
    if (nativeWantAgent == nullptr) {
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return;
    }
    return nativeWantAgent->OnCancel(errCode);
}

void FfiWantAgentTrigger(int64_t cjWantAgent, CJTriggerInfo triggerInfo,
    void (*callback)(CJCompleteData), int32_t *errCode)
{
    auto nativeWantAgent = OHOS::FFI::FFIData::GetData<CJWantAgent>(cjWantAgent);
    if (nativeWantAgent == nullptr) {
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return;
    }
    return nativeWantAgent->OnTrigger(triggerInfo, CJLambda::Create(callback), errCode);
}

int32_t FfiWantAgentGetOperationType(int64_t cjWantAgent, int32_t *errCode)
{
    auto nativeWantAgent = OHOS::FFI::FFIData::GetData<CJWantAgent>(cjWantAgent);
    if (nativeWantAgent == nullptr) {
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return -1;
    }
    return nativeWantAgent->OnGetOperationType(errCode);
}

bool FfiWantAgentEqual(int64_t cjWantAgentFirst, int64_t cjWantAgentSecond, int32_t *errCode)
{
    auto nativeWantAgentFirst = OHOS::FFI::FFIData::GetData<CJWantAgent>(cjWantAgentFirst);
    auto nativeWantAgentSecond = OHOS::FFI::FFIData::GetData<CJWantAgent>(cjWantAgentSecond);
    if (nativeWantAgentFirst == nullptr || nativeWantAgentSecond == nullptr) {
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return false;
    }
    return nativeWantAgentFirst->OnEqual(nativeWantAgentSecond->wantAgent_, errCode);
}
}
} // namespace FfiWantAgent
} // namespace OHOS