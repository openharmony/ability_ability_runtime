/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_SESSION_RECORD_H
#define OHOS_ABILITY_RUNTIME_SESSION_RECORD_H

#include <memory>

#include "cli_session_info.h"
#include "iremote_object.h"

namespace OHOS {
namespace CliTool {
class SessionRecord {
public:
    SessionRecord(std::shared_ptr<CliSessionInfo> sessinInfo, pid_t cliPid, sptr<IRemoteObject> callback)
        : callBack_(callback),
          cliPid_(cliPid),
          sessinInfo_(sessinInfo) {}
    ~SessionRecord() = default;

    inline void AddStartTime(int64_t startTime)
    {
        startTime_ = startTime;
    }

    inline sptr<IRemoteObject> GetCallback()
    {
        return callBack_;
    }

    inline std::shared_ptr<CliSessionInfo> GetCliSessionInfo()
    {
        return sessinInfo_;
    }

    inline int64_t GetStartTime()
    {
        return startTime_;
    }

    inline pid_t GetPid()
    {
        return cliPid_;
    }

private:
    sptr<IRemoteObject> callBack_;
    pid_t cliPid_;
    std::shared_ptr<CliSessionInfo> sessinInfo_;
    int64_t startTime_ = 0;
};

} // namespace CliTool
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_SESSION_RECORD_H
