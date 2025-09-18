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

#include "mock_my_flag.h"

#include "start_ability_utils.h"

namespace OHOS {
namespace AAFwk {
int MyFlag::startAbilityRet_ = 0;
sptr<AppExecFwk::IAppControlMgr> MyFlag::mockAppControlManager_ = nullptr;
AppExecFwk::AppJumpControlRule MyFlag::mockControlRule_;
int MyFlag::retGetAppJumpControlRule_ = 0;
bool MyFlag::retCallerGetApplicationInfo_ = false;
AppExecFwk::ApplicationInfo MyFlag::retCallerApplicationInfo_;
bool MyFlag::retTargetGetApplicationInfo_ = false;
AppExecFwk::ApplicationInfo MyFlag::retTargetApplicationInfo_;
int MyFlag::retVerifyAccessTokenId_ = 0;
std::string MyFlag::callerBundleName_;
int MyFlag::retGetNameForUid_ = 0;
bool MyFlag::retParseJumpInterceptorWant_ = false;
std::shared_ptr<StartAbilityInfo> StartAbilityUtils::startAbilityInfo = nullptr;
bool MyFlag::isStartIncludeAtomicService_ = false;
AppExecFwk::AbilityInfo MyFlag::retAbilityInfo_;
bool MyFlag::retQueryAbilityInfo_ = false;
std::shared_ptr<AppExecFwk::BundleMgrHelper> MyFlag::bundleMgrHelper_ = nullptr;
} // namespace AAFwk
} // namespace OHOS