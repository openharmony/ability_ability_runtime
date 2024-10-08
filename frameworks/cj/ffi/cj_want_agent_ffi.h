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

#ifndef CJ_WANT_AGENT_FFI_H
#define CJ_WANT_AGENT_FFI_H

#include <cstdint>

#include "application_context.h"
#include "want.h"
#include "want_agent.h"
#include "want_agent_constant.h"
#include "want_params.h"
#include "cj_common_ffi.h"
#include "cj_want_agent_utils.h"
#include "ffi_remote_data.h"

namespace OHOS {
namespace WantAgentCJ {

using namespace OHOS::AbilityRuntime::WantAgent;

class CJTriggerCompleteCallBack : public CompletedCallback {
public:
    CJTriggerCompleteCallBack();
    virtual ~CJTriggerCompleteCallBack();

public:
    void OnSendFinished(const AAFwk::Want &want, int resultCode, const std::string &resultData,
        const AAFwk::WantParams &resultExtras) override;
    void SetCallbackInfo(std::function<void(CJCompleteData)> callback);
    void SetWantAgentInstance(int64_t wantAgent);

private:
    std::function<void(CJCompleteData)> callback_;
    int64_t wantAgent_;
};

class CJWantAgent : public OHOS::FFI::FFIData {
    DECL_TYPE(CJWantAgent, OHOS::FFI::FFIData)
public:
    explicit CJWantAgent(std::shared_ptr<WantAgent> wantAgent)
        : wantAgent_(wantAgent) {};
    
    std::string OnGetBundleName(int32_t *errCode);
    int32_t OnGetUid(int32_t *errCode);
    void OnCancel(int32_t *errCode);
    void OnTrigger(CJTriggerInfo triggerInfo, std::function<void(CJCompleteData)> callback, int32_t *errCode);

private:
    int32_t UnWrapTriggerInfoParam(CJTriggerInfo cjTriggerInfo, std::function<void(CJCompleteData)> callback,
        std::shared_ptr<WantAgent> &wantAgent, TriggerInfo &triggerInfo,
        std::shared_ptr<CJTriggerCompleteCallBack> &triggerObj);

private:
    std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent_;
};

extern "C" {
    FFI_EXPORT int64_t FfiWantAgentGetWantAgent(CJWantAgentInfo info, int32_t *errCode);
    FFI_EXPORT char* FfiWantAgentGetBoundleName(int64_t cjWantAgent, int32_t *errCode);
    FFI_EXPORT int32_t FfiWantAgentGetUid(int64_t cjWantAgent, int32_t *errCode);
    FFI_EXPORT void FfiWantAgentCancel(int64_t cjWantAgent, int32_t *errCode);
    FFI_EXPORT void FfiWantAgentTrigger(int64_t cjWantAgent, CJTriggerInfo triggerInfo,
        void (*callback)(CJCompleteData), int32_t *errCode);
}

}
}
#endif // CJ_WANT_AGENT_FFI_H