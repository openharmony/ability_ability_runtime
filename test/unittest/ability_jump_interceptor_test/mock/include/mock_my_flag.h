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

#ifndef MOCK_MY_FLAG_H
#define MOCK_MY_FLAG_H

#include <vector>

#include "ability_info.h"
#include "app_control_interface.h"
#include "bundle_mgr_helper.h"

namespace OHOS {
namespace AAFwk {
class MyFlag {
public:
    static int startAbilityRet_;
    static sptr<AppExecFwk::IAppControlMgr> mockAppControlManager_;
    static AppExecFwk::AppJumpControlRule mockControlRule_;
    static int retGetAppJumpControlRule_;
    static std::shared_ptr<AppExecFwk::BundleMgrHelper> bundleMgrHelper_;
    static bool retCallerGetApplicationInfo_;
    static AppExecFwk::ApplicationInfo retCallerApplicationInfo_;
    static bool retTargetGetApplicationInfo_;
    static AppExecFwk::ApplicationInfo retTargetApplicationInfo_;
    static int retVerifyAccessTokenId_;
    static std::string callerBundleName_;
    static int retGetNameForUid_;
    static bool retParseJumpInterceptorWant_;
    static bool isStartIncludeAtomicService_;
    static AppExecFwk::AbilityInfo retAbilityInfo_;
    static bool retQueryAbilityInfo_;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif // MOCK_MY_FLAG_H