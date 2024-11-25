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

#include "error_msg_util.h"

#include "freeze_util.h"

namespace OHOS::AbilityRuntime {
ErrorMsgGuard::ErrorMsgGuard(sptr<IRemoteObject> token, uintptr_t scheduler, const std::string &name)
    : token_(token), errorKey_(ErrorMgsUtil::BuildErrorKey(scheduler, name))
{
    if (token != nullptr) {
        ErrorMgsUtil::GetInstance().AddErrorMsg(errorKey_, "");
    }
}

ErrorMsgGuard::ErrorMsgGuard(pid_t pid, uintptr_t scheduler, const std::string &name)
    : pid_(pid), errorKey_(ErrorMgsUtil::BuildErrorKey(scheduler, name))
{
    ErrorMgsUtil::GetInstance().AddErrorMsg(errorKey_, "");
}

ErrorMsgGuard::~ErrorMsgGuard()
{
    auto errorMsg = ErrorMgsUtil::GetInstance().DeleteErrorMsg(errorKey_);
    if (errorMsg.empty()) {
        return;
    }
    if (token_) {
        FreezeUtil::GetInstance().AppendLifecycleEvent(token_, errorMsg);
    } else {
        FreezeUtil::GetInstance().AddAppLifecycleEvent(pid_, errorMsg);
    }
}

ErrorMgsUtil &ErrorMgsUtil::GetInstance()
{
    static ErrorMgsUtil instance;
    return instance;
}

std::string ErrorMgsUtil::BuildErrorKey(uintptr_t scheduler, const std::string &name)
{
    return std::to_string(scheduler) + "#" + name;
}

void ErrorMgsUtil::AddErrorMsg(const std::string &key, const std::string &errorMsg)
{
    std::lock_guard lock(errorMsgMapMutex_);
    errorMsgMap_[key] = errorMsg;
}

bool ErrorMgsUtil::UpdateErrorMsg(const std::string &key, const std::string &errorMsg)
{
    std::lock_guard lock(errorMsgMapMutex_);
    auto it = errorMsgMap_.find(key);
    if (it == errorMsgMap_.end()) {
        return false;
    }
    it->second = errorMsg;
    return true;
}

std::string ErrorMgsUtil::DeleteErrorMsg(const std::string &key)
{
    std::lock_guard lock(errorMsgMapMutex_);
    auto it = errorMsgMap_.find(key);
    if (it == errorMsgMap_.end()) {
        return "";
    }
    auto result = std::move(it->second);
    errorMsgMap_.erase(it);
    return result;
}
}  // namespace OHOS::AbilityRuntime