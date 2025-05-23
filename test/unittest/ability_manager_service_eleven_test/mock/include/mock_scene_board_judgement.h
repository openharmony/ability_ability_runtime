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

#ifndef MOCK_SCENE_BOARD_JUDGEMENT_H
#define MOCK_SCENE_BOARD_JUDGEMENT_H

#include <fstream>
#include <gmock/gmock.h>
namespace OHOS {
namespace Rosen {
class SceneBoardJudgement final {
public:
    static SceneBoardJudgement& GetInstance();
    // Judge whether SceneBoard is enabled.
    static bool IsSceneBoardEnabled();

    MOCK_METHOD(bool, MockIsSceneBoardEnabled, (), (const));

private:
    // Dealing with Windows type end of line "\r\n".
    static std::ifstream& SafeGetLine(std::ifstream& configFile, std::string& line);
    static void InitWithConfigFile(const char* filePath, bool& enabled);
};
} // namespace Rosen
} // namespace OHOS

#endif // MOCK_SCENE_BOARD_JUDGEMENT_H
