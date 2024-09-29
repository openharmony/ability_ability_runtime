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
#include "cj_want_agent_ffi.h"
#include "cj_ability_runtime_error.h"
#include "cj_utils_ffi.h"

namespace OHOS {
namespace WantAgentCJ {

using namespace OHOS::AbilityRuntime;

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

extern "C" {
int64_t FfiWantAgentGetWantAgent(CJWantAgentInfo info, int32_t *errCode)
{
    std::shared_ptr<AAFwk::WantParams> extraInfo = 
        std::make_shared<AAFwk::WantParams>(OHOS::AAFwk::WantParamWrapper::ParseWantParams(info.extraInfos));
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
        OHOS::AbilityRuntime::WantAgent::WantAgent* pWantAgent = nullptr;
        if (wantAgent == nullptr) {
            *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
            return -1;
        } else {
            pWantAgent = new (std::nothrow) OHOS::AbilityRuntime::WantAgent::WantAgent(
                wantAgent->GetPendingWant());
        }
        if (pWantAgent == nullptr) {
            *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
            return -1;
        } else {
            auto nativeWantAgent = OHOS::FFI::FFIData::Create<CJWantAgent>(
                std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgent>(*pWantAgent));
            return nativeWantAgent->GetID();
        }
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

int32_t FfiWantAgentGetUidCallback(int64_t cjWantAgent, int32_t *errCode)
{
    auto nativeWantAgent = OHOS::FFI::FFIData::GetData<CJWantAgent>(cjWantAgent);
    if (nativeWantAgent == nullptr) {
        *errCode = ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER;
        return -1;
    }
    return nativeWantAgent->OnGetUid(errCode);
}
}

}
}