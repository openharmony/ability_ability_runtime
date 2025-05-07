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

#include "ani_want_agent.h"

#include "ability_runtime_error_util.h"
#include "hilog_tag_wrapper.h"
#include "start_options.h"
#include "want_agent_helper.h"
#include "ani_common_util.h"
#include "ani_common_want.h"
#include "ani_enum_convert.h"
#include "ani_common_start_options.h"

using namespace OHOS::AbilityRuntime;
namespace OHOS {
namespace {
constexpr int32_t ERR_NOT_OK = -1;
constexpr int32_t BUSINESS_ERROR_CODE_OK = 0;
constexpr int32_t PARAMETER_ERROR = -1;
constexpr const char* COMPLETE_DATA_IMPL_CLASS_NAME = "L@ohos/app/ability/wantAgent/wantAgent/CompleteDataImpl;";
constexpr const char* WANT_CLASS_NAME = "L@ohos/app/ability/Want/Want;";
constexpr const char* LONG_CLASS_NAME = "Lstd/core/Long;";
} // namespace

TriggerCompleteCallBack::TriggerCompleteCallBack()
{}

TriggerCompleteCallBack::~TriggerCompleteCallBack()
{}

void TriggerCompleteCallBack::SetCallbackInfo(ani_vm *vm, ani_ref call)
{
    triggerCompleteInfo_.vm = vm;
    triggerCompleteInfo_.call = call;
}

void TriggerCompleteCallBack::SetWantAgentInstance(std::shared_ptr<WantAgent> wantAgent)
{
    triggerCompleteInfo_.wantAgent = wantAgent;
}

void OnSendFinishedCallback(TriggerReceiveDataWorker *dataWorker)
{
    if (dataWorker == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "dataWorker null");
        return;
    }
    ani_vm *etsVm = dataWorker->vm;
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    if (etsVm == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "etsVm null");
        return;
    }
    if ((status = etsVm->GetEnv(ANI_VERSION_1, &env)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "status : %{public}d", status);
        return;
    }
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "env null");
        return;
    }
    ani_class cls {};
    ani_method method = nullptr;
    ani_object object = nullptr;
    if ((status = env->FindClass(COMPLETE_DATA_IMPL_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "status : %{public}d", status);
        return;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "status : %{public}d", status);
        return;
    }
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "status : %{public}d", status);
        return;
    }
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null object");
        return;
    }
    env->Object_SetPropertyByName_Ref(object, "info", EtsWantAgent::WrapWantAgent(env, dataWorker->wantAgent));
    env->Object_SetPropertyByName_Ref(object, "want", AppExecFwk::WrapWant(env, dataWorker->want));
    env->Object_SetPropertyByName_Double(object, "finalCode", static_cast<ani_double>(dataWorker->resultCode));
    env->Object_SetPropertyByName_Ref(object, "finalData", GetAniString(env, dataWorker->resultData));
    env->Object_SetPropertyByName_Ref(object, "extraInfo", AppExecFwk::WrapWantParams(env, dataWorker->resultExtras));

    ani_object error = CreateStsError(env, AbilityErrorCode::ERROR_OK);
    AsyncCallback(env, reinterpret_cast<ani_object>(dataWorker->call), error, object);
    env->GlobalReference_Delete(dataWorker->call);
}

void TriggerCompleteCallBack::OnSendFinished(
    const AAFwk::Want &want, int resultCode, const std::string &resultData, const AAFwk::WantParams &resultExtras)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "OnSendFinished");
    if (triggerCompleteInfo_.call == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "CallBack is nullptr");
        return;
    }
    TriggerReceiveDataWorker* dataWorker = new (std::nothrow) TriggerReceiveDataWorker();
    if (dataWorker == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "dataWorker null");
        return;
    }
    dataWorker->want = want;
    dataWorker->resultCode = resultCode;
    dataWorker->resultData = resultData;
    dataWorker->resultExtras = resultExtras;
    dataWorker->vm = triggerCompleteInfo_.vm;
    dataWorker->call = triggerCompleteInfo_.call;
    if (triggerCompleteInfo_.wantAgent != nullptr) {
        dataWorker->wantAgent = new WantAgent(triggerCompleteInfo_.wantAgent->GetPendingWant());
    }
    OnSendFinishedCallback(dataWorker);
    if (dataWorker != nullptr) {
        if (dataWorker->wantAgent != nullptr) {
            delete dataWorker->wantAgent;
            dataWorker->wantAgent = nullptr;
        }
        delete dataWorker;
        dataWorker = nullptr;
    }
}

EtsWantAgent &EtsWantAgent::GetInstance()
{
    static EtsWantAgent instance;
    return instance;
}

void EtsWantAgent::GetBundleName(ani_env *env, ani_object agent, ani_object call)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "called");
    GetInstance().OnGetBundleName(env, agent, call);
};

void EtsWantAgent::GetUid(ani_env *env, ani_object agent, ani_object call)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "called");
    GetInstance().OnGetUid(env, agent, call);
};

void EtsWantAgent::Cancel(ani_env *env, ani_object agent, ani_object call)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "called");
    GetInstance().OnCancel(env, agent, call);
};

void EtsWantAgent::Equal(ani_env *env, ani_object agent, ani_object otherAgent, ani_object call)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "called");
    GetInstance().OnEqual(env, agent, otherAgent, call);
};

void EtsWantAgent::GetWant(ani_env *env, ani_object agent, ani_object call)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "called");
    GetInstance().OnGetWant(env, agent, call);
};

void EtsWantAgent::GetOperationType(ani_env *env, ani_object agent, ani_object call)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "called");
    GetInstance().OnGetOperationType(env, agent, call);
};

void EtsWantAgent::Trigger(ani_env *env, ani_object agent, ani_object triggerInfoObj, ani_object call)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "called");
    GetInstance().OnTrigger(env, agent, triggerInfoObj, call);
};

void EtsWantAgent::GetWantAgent(ani_env *env, ani_object info, ani_object call)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "called");
    GetInstance().OnGetWantAgent(env, info, call);
}


void EtsWantAgent::OnGetBundleName(ani_env *env, ani_object agent, ani_object call)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "env null");
        return;
    }
    WantAgent* pWantAgent = nullptr;
    ErrCode resultCode = ERR_OK;
    ani_object aniObject = CreateStsError(env, AbilityErrorCode::ERROR_OK);
    UnwrapWantAgent(env, agent, reinterpret_cast<void **>(&pWantAgent));
    if (pWantAgent == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Parse pWantAgent failed");
        aniObject = CreateStsErrorByNativeErr(env, ERR_NOT_OK);
#ifdef ENABLE_ERRCODE
        ThrowStsInvalidParamError(env, "Parse pWantAgent failed. Agent must be a WantAgent.");
        return;
#else
        AsyncCallback(env, call, aniObject, nullptr);
        return;
#endif
    }
    std::shared_ptr<WantAgent> wantAgent = std::make_shared<WantAgent>(*pWantAgent);
    std::string bundleName = "";
    resultCode = WantAgentHelper::GetBundleName(wantAgent, bundleName);
    if (resultCode != ERR_OK) {
        aniObject = CreateStsErrorByNativeErr(env, resultCode);
    }
    ani_string aniBundleName = GetAniString(env, bundleName);
    AsyncCallback(env, call, aniObject, reinterpret_cast<ani_object>(aniBundleName));
}

void EtsWantAgent::OnGetUid(ani_env *env, ani_object agent, ani_object call)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "env null");
        return;
    }
    WantAgent* pWantAgent = nullptr;
    ErrCode resultCode = ERR_OK;
    ani_object aniObject = CreateStsError(env, AbilityErrorCode::ERROR_OK);
    UnwrapWantAgent(env, agent, reinterpret_cast<void **>(&pWantAgent));
    if (pWantAgent == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Parse pWantAgent failed");
        aniObject = CreateStsErrorByNativeErr(env, ERR_NOT_OK);
#ifdef ENABLE_ERRCODE
        ThrowStsInvalidParamError(env, "Parse pWantAgent failed. Agent must be a WantAgent.");
        return;
#else
        AsyncCallback(env, call, aniObject, nullptr);
        return;
#endif
    }
    std::shared_ptr<WantAgent> wantAgent = std::make_shared<WantAgent>(*pWantAgent);
    int uid = -1;
    resultCode = WantAgentHelper::GetUid(wantAgent, uid);
    if (resultCode != ERR_OK) {
        aniObject = CreateStsErrorByNativeErr(env, resultCode);
    }
    AsyncCallback(env, call, aniObject, createDouble(env, static_cast<ani_double>(uid)));
}

void EtsWantAgent::OnCancel(ani_env *env, ani_object agent, ani_object call)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "env null");
        return;
    }
    WantAgent* pWantAgent = nullptr;
    ErrCode resultCode = ERR_OK;
    ani_object aniObject = CreateStsError(env, AbilityErrorCode::ERROR_OK);
    UnwrapWantAgent(env, agent, reinterpret_cast<void **>(&pWantAgent));
    if (pWantAgent == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Parse pWantAgent failed");
        aniObject = CreateStsErrorByNativeErr(env, ERR_NOT_OK);
#ifdef ENABLE_ERRCODE
        ThrowStsInvalidParamError(env, "Parse pWantAgent failed. Agent must be a WantAgent.");
        return;
#else
        AsyncCallback(env, call, aniObject, nullptr);
        return;
#endif
    }
    std::shared_ptr<WantAgent> wantAgent = std::make_shared<WantAgent>(*pWantAgent);
    resultCode = WantAgentHelper::Cancel(wantAgent);
    if (resultCode != NO_ERROR) {
        aniObject = CreateStsErrorByNativeErr(env, resultCode);
    }
    AsyncCallback(env, call, aniObject, nullptr);
}

void EtsWantAgent::OnEqual(ani_env *env, ani_object agent, ani_object otherAgent, ani_object call)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "env null");
        return;
    }
    WantAgent* pWantAgentFirst = nullptr;
    WantAgent* pWantAgentSecond = nullptr;
    ErrCode resultCode = ERR_OK;
    ani_object aniObject = CreateStsError(env, AbilityErrorCode::ERROR_OK);
    UnwrapWantAgent(env, agent, reinterpret_cast<void **>(&pWantAgentFirst));
    UnwrapWantAgent(env, otherAgent, reinterpret_cast<void **>(&pWantAgentSecond));
    if (pWantAgentFirst == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Parse pWantAgentFirst failed");
        aniObject = CreateStsErrorByNativeErr(env, ERR_NOT_OK);
#ifdef ENABLE_ERRCODE
        ThrowStsInvalidParamError(env, "Parse pWantAgent failed. Agent must be a WantAgent.");
        return;
#else
        AsyncCallback(env, call, aniObject, nullptr);
        return;
#endif
    }
    if (pWantAgentSecond == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Parse pWantAgentSecond failed");
        aniObject = CreateStsErrorByNativeErr(env, ERR_NOT_OK);
#ifdef ENABLE_ERRCODE
        ThrowStsInvalidParamError(env, "Parse pWantAgent failed. Agent must be a WantAgent.");
        return;
#else
        AsyncCallback(env, call, aniObject, nullptr);
        return;
#endif
    }
    std::shared_ptr<WantAgent> wantAgentFirst = std::make_shared<WantAgent>(*pWantAgentFirst);
    std::shared_ptr<WantAgent> wantAgentSecond = std::make_shared<WantAgent>(*pWantAgentSecond);
    resultCode = WantAgentHelper::IsEquals(wantAgentFirst, wantAgentSecond);
    bool ret = false;
    if (resultCode == ERR_NOT_OK) {
        ret = false;
    } else if (resultCode == ERR_OK) {
        ret = true;
    } else {
        aniObject = CreateStsErrorByNativeErr(env, resultCode);
    }
    AsyncCallback(env, call, aniObject, createBoolean(env, static_cast<ani_boolean>(ret)));
}

void EtsWantAgent::OnGetWant(ani_env *env, ani_object agent, ani_object call)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "env null");
        return;
    }
    WantAgent* pWantAgent = nullptr;
    ani_object aniObject = CreateStsError(env, AbilityErrorCode::ERROR_OK);
    UnwrapWantAgent(env, agent, reinterpret_cast<void **>(&pWantAgent));
    if (pWantAgent == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Parse pWantAgent failed");
        aniObject = CreateStsErrorByNativeErr(env, ERR_NOT_OK);
#ifdef ENABLE_ERRCODE
        ThrowStsInvalidParamError(env, "Parse pWantAgent failed. Agent must be a WantAgent.");
        return;
#else
        AsyncCallback(env, call, aniObject, nullptr);
        return;
#endif
    }
    std::shared_ptr<WantAgent> wantAgent = std::make_shared<WantAgent>(*pWantAgent);
    std::shared_ptr<Want> want = WantAgentHelper::GetWant(wantAgent);
    ani_object wantAniObj = nullptr;
    if (want == nullptr) {
        aniObject = CreateStsError(env, ERR_NOT_OK, "WantAgentHelper::GetWant result nullptr.");
        ani_class cls = nullptr;
        ani_method method = nullptr;
        ani_object object = nullptr;
        env->FindClass(WANT_CLASS_NAME, &cls);
        env->Class_FindMethod(cls, "<ctor>", ":V", &method);
        env->Object_New(cls, method, &object);
        wantAniObj = object;
    } else {
        wantAniObj = AppExecFwk::WrapWant(env, *want);
    }
    AsyncCallback(env, call, aniObject, wantAniObj);
}

void EtsWantAgent::OnGetOperationType(ani_env *env, ani_object agent, ani_object call)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "env null");
        return;
    }
    WantAgent* pWantAgent = nullptr;
    ani_object aniObject = CreateStsError(env, AbilityErrorCode::ERROR_OK);
    UnwrapWantAgent(env, agent, reinterpret_cast<void **>(&pWantAgent));
    if (pWantAgent == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Parse pWantAgent failed");
        aniObject = CreateStsErrorByNativeErr(env, ERR_NOT_OK);
#ifdef ENABLE_ERRCODE
        ThrowStsInvalidParamError(env, "Parse pWantAgent failed. Agent must be a WantAgent.");
        return;
#else
        AsyncCallback(env, call, aniObject, nullptr);
        return;
#endif
    }
    std::shared_ptr<WantAgent> wantAgent = std::make_shared<WantAgent>(*pWantAgent);
    auto ret = WantAgentHelper::GetType(wantAgent);
    AsyncCallback(env, call, aniObject, createDouble(env, static_cast<ani_double>(ret)));
}

int32_t EtsWantAgent::GetWantAgentParam(ani_env *env, ani_object info, WantAgentWantsParas &paras)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "called");
    ani_status status = ANI_ERROR;
    ani_ref wantsRef = nullptr;
    if ((status = env->Object_GetPropertyByName_Ref(info, "wants", &wantsRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "status : %{public}d", status);
        return PARAMETER_ERROR;
    }
    if (wantsRef == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null wantsRef");
        return PARAMETER_ERROR;
    }
    ani_array_ref wantsArr = reinterpret_cast<ani_array_ref>(wantsRef);
    ani_size length = 0;
    if ((status = env->Object_GetPropertyByName_Ref(info, "wants", &wantsRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "status : %{public}d", status);
        return PARAMETER_ERROR;
    }
    if ((status = env->Array_GetLength(wantsArr, &length)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "status : %{public}d", status);
        return PARAMETER_ERROR;
    }
    for (size_t i = 0; i < length; i++) {
        ani_ref wantRef = nullptr;
        std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
        if ((status = env->Array_Get_Ref(wantsArr, i, &wantRef)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::WANTAGENT, "status : %{public}d", status);
            return PARAMETER_ERROR;
        }
        if (!AppExecFwk::UnwrapWant(env, reinterpret_cast<ani_object>(wantRef), *want)) {
            TAG_LOGE(AAFwkTag::WANTAGENT, "UnwrapWant  failed");
            return PARAMETER_ERROR;
        }
        paras.wants.emplace_back(want);
    }

    ani_boolean hasActionType = true;
    ani_ref actionTypeRef = nullptr;
    if (!AppExecFwk::GetPropertyRef(env, info, "actionType", actionTypeRef, hasActionType)) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "GetPropertyRef failed");
        return PARAMETER_ERROR;
    }
    if (!hasActionType) {
        AAFwk::AniEnumConvertUtil::EnumConvert_StsToNative(
            env, reinterpret_cast<ani_enum_item>(actionTypeRef), paras.operationType);
    }

    ani_double dRequestCode = 0.0;
    if ((status = env->Object_GetPropertyByName_Double(info, "requestCode", &dRequestCode)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "status : %{public}d", status);
        return PARAMETER_ERROR;
    }
    paras.requestCode = dRequestCode;

    ani_boolean hasActionFlags = true;
    ani_ref actionFlagsRef = nullptr;
    if (!AppExecFwk::GetPropertyRef(env, info, "actionFlags", actionFlagsRef, hasActionFlags)) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "GetPropertyRef failed");
        return PARAMETER_ERROR;
    }
    ani_array_ref actionFlagsArr = reinterpret_cast<ani_array_ref>(actionFlagsRef);
    if (!hasActionFlags) {
        ani_size actionFlagsLen = 0;
        if ((status = env->Array_GetLength(actionFlagsArr, &actionFlagsLen)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::WANTAGENT, "status : %{public}d", status);
            return PARAMETER_ERROR;
        }
        for (size_t i = 0; i < actionFlagsLen; i++) {
            ani_ref actionFlagRef = nullptr;
            int32_t actionFlag = 0;
            if ((status = env->Array_Get_Ref(actionFlagsArr, i, &actionFlagRef)) != ANI_OK) {
                TAG_LOGE(AAFwkTag::WANTAGENT, "status : %{public}d", status);
                return PARAMETER_ERROR;
            }
            AAFwk::AniEnumConvertUtil::EnumConvert_StsToNative(
                env, reinterpret_cast<ani_object>(actionFlagRef), actionFlag);
            paras.wantAgentFlags.emplace_back(static_cast<WantAgentConstant::Flags>(actionFlag));
        }
    }
    return BUSINESS_ERROR_CODE_OK;
}

void EtsWantAgent::OnTrigger(ani_env *env, ani_object agent, ani_object triggerInfoObj, ani_object call)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "env null");
        return;
    }
    std::shared_ptr<WantAgent> wantAgent = nullptr;
    WantAgent* pWantAgent = nullptr;
    TriggerInfo triggerInfo;
    UnwrapWantAgent(env, agent, reinterpret_cast<void **>(&pWantAgent));
    if (pWantAgent == nullptr) {
        ThrowStsInvalidParamError(env, "Parse pWantAgent failed. Agent must be a WantAgent.");
        return;
    }
    wantAgent = std::make_shared<WantAgent>(*pWantAgent);
    int32_t ret = GetTriggerInfo(env, triggerInfoObj, triggerInfo);
    if (ret != 0) {
        ThrowStsInvalidParamError(env, "Get trigger info error. TriggerInfo must be a TriggerInfo.");
        return;
    }
    auto triggerObj = std::make_shared<TriggerCompleteCallBack>();
    ani_vm *etsVm = nullptr;
    env->GetVM(&etsVm);
    ani_ref callbackRef = nullptr;
    env->GlobalReference_Create(call, &callbackRef);
    triggerObj->SetCallbackInfo(etsVm, callbackRef);
    triggerObj->SetWantAgentInstance(std::make_shared<WantAgent>(pWantAgent->GetPendingWant()));
    WantAgentHelper::TriggerWantAgent(wantAgent, triggerObj, triggerInfo);
}

int32_t EtsWantAgent::GetTriggerInfo(ani_env *env, ani_object triggerInfoObj, TriggerInfo &triggerInfo)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "called");
    ani_status status = ANI_ERROR;

    ani_double dCode { 0.0 };
    if ((status = env->Object_GetPropertyByName_Double(triggerInfoObj, "code", &dCode)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "status : %{public}d", status);
        return PARAMETER_ERROR;
    }
    const int32_t code = static_cast<int32_t>(dCode);

    std::shared_ptr<AAFwk::Want> want = nullptr;
    ani_ref wantRef = nullptr;
    ani_boolean isUndefined = true;
    if (!AppExecFwk::GetPropertyRef(env, triggerInfoObj, "want", wantRef, isUndefined)) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "GetPropertyRef failed");
        return PARAMETER_ERROR;
    }
    if (!isUndefined) {
        want = std::make_shared<AAFwk::Want>();
        if (!AppExecFwk::UnwrapWant(env, reinterpret_cast<ani_object>(wantRef), *want)) {
            TAG_LOGE(AAFwkTag::WANTAGENT, "UnwrapWant failed");
            return PARAMETER_ERROR;
        }
    }

    std::shared_ptr<AAFwk::WantParams> extraInfo = nullptr;
    ani_ref extraInfoRef = nullptr;
    if (!AppExecFwk::GetPropertyRef(env, triggerInfoObj, "extraInfos", extraInfoRef, isUndefined)) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "GetPropertyRef failed");
        return PARAMETER_ERROR;
    }
    if (isUndefined) {
        if (!AppExecFwk::GetPropertyRef(env, triggerInfoObj, "extraInfo", extraInfoRef, isUndefined)) {
            TAG_LOGE(AAFwkTag::WANTAGENT, "GetPropertyRef failed");
            return PARAMETER_ERROR;
        }
    }
    if (!isUndefined) {
        extraInfo = std::make_shared<AAFwk::WantParams>();
        if (!UnwrapWantParams(env, extraInfoRef, *extraInfo)) {
            TAG_LOGE(AAFwkTag::WANTAGENT, "Convert extraInfo failed");
            return PARAMETER_ERROR;
        }
    }

    std::shared_ptr<AAFwk::StartOptions> startOptions = nullptr;
    ani_ref startOptionsRef = nullptr;
    if (!AppExecFwk::GetPropertyRef(env, triggerInfoObj, "startOptions", startOptionsRef, isUndefined)) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "GetPropertyRef failed");
        return PARAMETER_ERROR;
    }
    if (!isUndefined) {
        startOptions = std::make_shared<AAFwk::StartOptions>();
        if (!UnwrapStartOptionsWithProcessOption(env, reinterpret_cast<ani_object>(startOptionsRef), *startOptions)) {
            TAG_LOGE(AAFwkTag::WANTAGENT, "UnwrapStartOptionsWithProcessOption failed");
            return PARAMETER_ERROR;
        }
    }

    std::string permission = "";
    TriggerInfo triggerInfoData(permission, extraInfo, want, startOptions, code);
    triggerInfo = triggerInfoData;
    return BUSINESS_ERROR_CODE_OK;
}

void EtsWantAgent::OnGetWantAgent(ani_env *env, ani_object info, ani_object call)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "env null");
        return;
    }
    std::shared_ptr<WantAgentWantsParas> parasobj = std::make_shared<WantAgentWantsParas>();
    int32_t ret = GetWantAgentParam(env, info, *parasobj);
    if (ret != 0) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Failed to get wantAgent parameter. Agent must be a WantAgent.");
        ThrowStsInvalidParamError(env, "Failed to get wantAgent parameter. Agent must be a WantAgent.");
        return;
    }
    std::shared_ptr<AAFwk::WantParams> extraInfo = std::make_shared<AAFwk::WantParams>(parasobj->extraInfo);
    WantAgentInfo wantAgentInfo(parasobj->requestCode,
                                static_cast<WantAgentConstant::OperationType>(parasobj->operationType),
                                parasobj->wantAgentFlags,
                                parasobj->wants,
                                extraInfo);
    auto context = OHOS::AbilityRuntime::Context::GetApplicationContext();
    std::shared_ptr<WantAgent> wantAgent = nullptr;
    WantAgentHelper::GetWantAgent(context, wantAgentInfo, wantAgent);

    WantAgent* pWantAgent = nullptr;
    ani_object error = CreateStsErrorByNativeErr(env, ERR_NOT_OK);
    ani_object retObj = createLong(env, 0);
    if (wantAgent != nullptr) {
        pWantAgent = new (std::nothrow) WantAgent(wantAgent->GetPendingWant());
        error = CreateStsError(env, AbilityErrorCode::ERROR_OK);
        retObj = WrapWantAgent(env, pWantAgent);
    }
    AsyncCallback(env, call, error, retObj);
}

ani_object EtsWantAgent::WrapWantAgent(ani_env *env, WantAgent *wantAgent)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "called");
    if (wantAgent == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "wantAgent null");
        return nullptr;
    }
    ani_long pWantAgent = reinterpret_cast<ani_long>(wantAgent);
    ani_object longObj =  createLong(env, pWantAgent);
    if (longObj == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null object");
        return nullptr;
    }
    return longObj;
}

void EtsWantAgent::UnwrapWantAgent(ani_env *env, ani_object agent, void** result)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "called");
    if (agent == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "agent null");
        return;
    }
    ani_long param_value;
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    ani_method method {};
    if ((status = env->FindClass(LONG_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "status : %{public}d", status);
    }
    if ((status = env->Class_FindMethod(cls, "unboxed", nullptr, &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "status : %{public}d", status);
    }
    if ((status = env->Object_CallMethod_Long(agent, method, &param_value)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "status : %{public}d", status);
    }
    *result = reinterpret_cast<void*>(param_value);
}

bool BindNativeFunctions(ani_env *env, ani_namespace &ns)
{
    ani_status status = ANI_ERROR;
    if ((status = env->FindNamespace("L@ohos/app/ability/wantAgent/wantAgent;", &ns)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "status: %{public}d", status);
        return false;
    }
    std::array functions = {
        ani_native_function { "nativeGetBundleName", nullptr, reinterpret_cast<void*>(EtsWantAgent::GetBundleName) },
        ani_native_function { "nativeGetUid", nullptr, reinterpret_cast<void*>(EtsWantAgent::GetUid) },
        ani_native_function {
            "nativeGetOperationType", nullptr, reinterpret_cast<void*>(EtsWantAgent::GetOperationType) },
        ani_native_function { "nativeCancel", nullptr, reinterpret_cast<void*>(EtsWantAgent::Cancel) },
        ani_native_function { "nativeEqual", nullptr, reinterpret_cast<void*>(EtsWantAgent::Equal) },
        ani_native_function { "nativeTrigger", nullptr, reinterpret_cast<void*>(EtsWantAgent::Trigger) },
        ani_native_function { "nativeGetWant", nullptr, reinterpret_cast<void*>(EtsWantAgent::GetWant) },
        ani_native_function { "nativeGetWantAgent", nullptr, reinterpret_cast<void*>(EtsWantAgent::GetWantAgent) },
    };
    if ((status = env->Namespace_BindNativeFunctions(ns, functions.data(), functions.size())) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "status: %{public}d", status);
        return false;
    }
    return true;
}

void EtsWantAgentInit(ani_env *env)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "env null");
        return;
    }
    ani_namespace ns;
    if (!BindNativeFunctions(env, ns)) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "BindNativeFunctions failed");
        return;
    }
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "ANI_Constructor");
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "status : %{public}d", status);
        return ANI_NOT_FOUND;
    }

    EtsWantAgentInit(env);
    *result = ANI_VERSION_1;
    return ANI_OK;
}
}
}  // namespace OHOS
