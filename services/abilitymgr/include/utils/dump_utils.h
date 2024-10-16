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

#ifndef OHOS_ABILITY_RUNTIME_DUMP_UTILS_H
#define OHOS_ABILITY_RUNTIME_DUMP_UTILS_H

#include <string>

namespace OHOS {
namespace AAFwk {
/**
 * @class DumpUtils
 * provides dump utilities.
 */
class DumpUtils final {
public:
    enum DumpKey {
        // dump all
        KEY_DUMP_ALL = 0,

        // dump stack list
        KEY_DUMP_STACK_LIST,

        // dump stack
        KEY_DUMP_STACK,

        // dump mission
        KEY_DUMP_MISSION,

        // dump top ability
        KEY_DUMP_TOP_ABILITY,

        // dump wait queue
        KEY_DUMP_WAIT_QUEUE,

        // dump service
        KEY_DUMP_SERVICE,

        // dump data
        KEY_DUMP_DATA,

        // dump focus ability
        KEY_DUMP_FOCUS_ABILITY,

        // dump window mode
        KEY_DUMP_WINDOW_MODE,

        // dump mission list
        KEY_DUMP_MISSION_LIST,

        // dump mission info
        KEY_DUMP_MISSION_INFOS,
    };

    enum DumpsysKey {
        // dump system all
        KEY_DUMP_SYS_ALL = 0,

        // dump system mission list
        KEY_DUMP_SYS_MISSION_LIST,

        // dump system ability
        KEY_DUMP_SYS_ABILITY,

        // dump system service
        KEY_DUMP_SYS_SERVICE,

        // dump system pending
        KEY_DUMP_SYS_PENDING,

        // dump system process
        KEY_DUMP_SYS_PROCESS,

        // dump system data
        KEY_DUMP_SYS_DATA,
    };

    /**
     * DumpMapOne, dump map first function.
     *
     * @param argString The argument string.
     * @return The pair of the dump result and the dump key.
     */
    static std::pair<bool, DumpUtils::DumpKey> DumpMapOne(std::string argString);

    /**
     * DumpMapTwo, dump map second function.
     *
     * @param argString The argument string.
     * @return The pair of the dump result and the dump key.
     */
    static std::pair<bool, DumpUtils::DumpKey> DumpMapTwo(std::string argString);

    /**
     * DumpMap, dump map function.
     *
     * @param argString The argument string.
     * @return The pair of the dump result and the dump key.
     */
    static std::pair<bool, DumpUtils::DumpKey> DumpMap(std::string argString);

    /**
     * DumpsysMap, dump system map function.
     *
     * @param argString The argument string.
     * @return The pair of the dump result and the dump key.
     */
    static std::pair<bool, DumpUtils::DumpsysKey> DumpsysMap(std::string argString);
};
}  // namespace AAFwk
}  // namespace OHOS
#endif //OHOS_ABILITY_RUNTIME_DUMP_UTILS_H
