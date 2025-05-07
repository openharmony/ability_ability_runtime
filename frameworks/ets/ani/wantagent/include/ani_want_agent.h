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

#ifndef OHOS_ABILITY_RUNTIME_ANI_WANT_AGENT_H
#define OHOS_ABILITY_RUNTIME_ANI_WANT_AGENT_H

#include "ability.h"
#include "completed_callback.h"
#include "context/application_context.h"
#include "sts_error_utils.h"
#include "sts_runtime.h"
#include "trigger_info.h"
#include "want.h"
#include "want_agent.h"
#include "want_agent_constant.h"
#include "want_params.h"

namespace OHOS {
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime::WantAgent;

struct CallbackInfo {
    std::shared_ptr<WantAgent> wantAgent;
    ani_vm *vm = nullptr;
    ani_ref call = nullptr;
};

struct TriggerReceiveDataWorker {
    WantAgent* wantAgent;
    AAFwk::Want want;
    int resultCode;
    std::string resultData;
    AAFwk::WantParams resultExtras;
    ani_vm *vm = nullptr;
    ani_ref call = nullptr;
};

struct WantAgentWantsParas {
    std::vector<std::shared_ptr<AAFwk::Want>> wants = {};
    int32_t operationType = -1;
    int32_t requestCode = -1;
    std::vector<WantAgentConstant::Flags> wantAgentFlags = {};
    AAFwk::WantParams extraInfo = {};
};

class EtsWantAgent : public std::enable_shared_from_this<EtsWantAgent> {
public:
    EtsWantAgent() = default;
    ~EtsWantAgent() = default;
    static EtsWantAgent &GetInstance();
    static void Equal(ani_env *env, ani_object agent, ani_object otherAgent, ani_object call);
    static void GetWant(ani_env *env, ani_object agent, ani_object call);
    static void GetOperationType(ani_env *env, ani_object agent, ani_object call);
    static void GetBundleName(ani_env *env, ani_object agent, ani_object call);
    static void GetUid(ani_env *env, ani_object agent, ani_object call);
    static void Cancel(ani_env *env, ani_object agent, ani_object call);
    static void Trigger(ani_env *env, ani_object agent, ani_object triggerInfoObj, ani_object call);
    static void GetWantAgent(ani_env *env, ani_object info, ani_object call);

private:
    void OnEqual(ani_env *env, ani_object agent, ani_object otherAgent, ani_object call);
    void OnGetWant(ani_env *env, ani_object agent, ani_object call);
    void OnGetOperationType(ani_env *env, ani_object agent, ani_object call);
    void OnGetBundleName(ani_env *env, ani_object agent, ani_object call);
    void OnGetUid(ani_env *env, ani_object agent, ani_object call);
    void OnCancel(ani_env *env, ani_object agent, ani_object call);
    void OnTrigger(ani_env *env, ani_object agent, ani_object triggerInfoObj, ani_object call);
    void OnGetWantAgent(ani_env *env, ani_object info, ani_object call);
    int32_t GetTriggerInfo(ani_env *env, ani_object triggerInfoObj, TriggerInfo &triggerInfo);
    int32_t GetWantAgentParam(ani_env *env, ani_object info, WantAgentWantsParas &paras);
};

class TriggerCompleteCallBack : public CompletedCallback {
public:
    TriggerCompleteCallBack();
    virtual ~TriggerCompleteCallBack();

public:
    void OnSendFinished(const AAFwk::Want &want, int resultCode, const std::string &resultData,
        const AAFwk::WantParams &resultExtras) override;
    void SetCallbackInfo(ani_vm *vm, ani_ref call);
    void SetWantAgentInstance(std::shared_ptr<WantAgent> wantAgent);

private:
    CallbackInfo triggerCompleteInfo_;
};
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_ANI_WANT_AGENT_H
