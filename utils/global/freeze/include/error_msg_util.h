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

#ifndef OHOS_ABILITY_RUNTIME_ERROR_MSG_UTIL_H
#define OHOS_ABILITY_RUNTIME_ERROR_MSG_UTIL_H

#include <mutex>
#include <string>
#include <unordered_map>

#include "iremote_object.h"

namespace OHOS::AbilityRuntime {
class ErrorMsgGuard {
public:
    ErrorMsgGuard(sptr<IRemoteObject> token, uintptr_t scheduler, const std::string &name); // for ability
    ErrorMsgGuard(pid_t pid, uintptr_t scheduler, const std::string &name); // for app
    ~ErrorMsgGuard();

    ErrorMsgGuard(const ErrorMsgGuard &) = delete;
    void operator=(const ErrorMsgGuard &) = delete;
private:
    sptr<IRemoteObject> token_; // token, determines ability or app
    pid_t pid_ = 0;
    std::string errorKey_;
};

class ErrorMgsUtil {
public:
    ErrorMgsUtil& operator=(const ErrorMgsUtil&) = delete;
    ErrorMgsUtil(const ErrorMgsUtil&) = delete;
    virtual ~ErrorMgsUtil() = default;
    static ErrorMgsUtil& GetInstance();
    static std::string BuildErrorKey(uintptr_t scheduler, const std::string &name);

    void AddErrorMsg(const std::string &key, const std::string &errorMsg);
    bool UpdateErrorMsg(const std::string &key, const std::string &errorMsg);
    std::string DeleteErrorMsg(const std::string &key);
private:
    ErrorMgsUtil() = default;

    std::mutex errorMsgMapMutex_;
    std::unordered_map<std::string, std::string> errorMsgMap_;
};
}  // namespace OHOS::AbilityRuntime
#endif  // OHOS_ABILITY_RUNTIME_ERROR_MSG_UTIL_H