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

namespace OHOS {
namespace AAFwk {
int MyFlag::startAbilityRet_ = 0;
sptr<AppExecFwk::IAppControlMgr> MyFlag::mockAppControlManager_ = nullptr;
std::vector<AppExecFwk::DisposedRule> MyFlag::mockDisposedRuleList_;
int MyFlag::retGetAbilityRunningControlRule_ = 0;
bool MyFlag::retCreateModalUIExtension_ = false;
int MyFlag::retAbilityRecordCreateModalUIExtension_ = 0;
std::shared_ptr<AbilityRecord> MyFlag::abilityRecord_ = nullptr;
sptr<AppExecFwk::MockAppMgrService> MyFlag::mockAppMgr_ = nullptr;
std::shared_ptr<AppExecFwk::BundleMgrHelper> MyFlag::bundleMgrHelper_ = nullptr;
int MyFlag::edmCode_ = 0;
} // namespace AAFwk
} // namespace OHOS