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

#ifndef MOCK_CONFIG_POLICY_UTILS_H
#define MOCK_CONFIG_POLICY_UTILS_H

#include <string>

namespace OHOS {
namespace AbilityRuntime {
class MockConfigPolicyUtils {
public:
    static MockConfigPolicyUtils& GetInstance();

    MockConfigPolicyUtils() = default;
    ~MockConfigPolicyUtils();
    const char* GetOneCfgFilePath();
    void SetOneCfgFilePathIsNull();
    void SetOneCfgFilePath(std::string path, bool isCreate = false, bool isRoot = false);
    bool GetRealPathStatus();
    void SetRealPathIsNull(bool isNull);
private:
    std::string oneCfgFilePath_ = "";
    bool oneCfgFilePathIsNull_ = false;
    bool realPathIsNull_ = false;
};
}
}

#endif // MOCK_CONFIG_POLICY_UTILS_H