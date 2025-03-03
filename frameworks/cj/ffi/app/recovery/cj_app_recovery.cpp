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

#include "cj_app_recovery.h"

#include "app_recovery.h"
#include "cj_ability_context.h"
#include "ffi_remote_data.h"
#include "hilog_tag_wrapper.h"
#include "want.h"
#include "want_params.h"

using namespace OHOS::AbilityRuntime;
using namespace OHOS::AppExecFwk;

CJ_EXPORT void FFIAppRecoveryEnable(int32_t restartFlag, int32_t saveOccasionFlag, int32_t saveModeFlag)
{
    AppRecovery::GetInstance().EnableAppRecovery(static_cast<uint16_t>(restartFlag),
        static_cast<uint16_t>(saveOccasionFlag), static_cast<uint16_t>(saveModeFlag));
}

CJ_EXPORT void FFIAppRecoveryRestartApp()
{
    AppRecovery::GetInstance().ScheduleRecoverApp(StateReason::DEVELOPER_REQUEST);
}

CJ_EXPORT bool FFIAppRecoverySaveAppState(int64_t ctxId)
{
    uintptr_t ability = 0;
    if (ctxId != 0) {
        auto cjContext = OHOS::FFI::FFIData::GetData<CJAbilityContext>(ctxId);
        if (cjContext == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "CJAbilityContext id is invalid.");
            return false;
        }
        ability = reinterpret_cast<uintptr_t>(cjContext->GetAbilityContext().get());
    }
    return AppRecovery::GetInstance().ScheduleSaveAppState(StateReason::DEVELOPER_REQUEST, ability);
}

CJ_EXPORT void FFIAppRecoverySetRestartWant(WantHandle want)
{
    auto actualWant = reinterpret_cast<OHOS::AAFwk::Want*>(want);
    if (!actualWant) {
        return;
    }
    std::shared_ptr<OHOS::AAFwk::Want> paramWant = std::make_shared<OHOS::AAFwk::Want>();
    *paramWant = *actualWant;
    AppRecovery::GetInstance().SetRestartWant(paramWant);
}
