/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
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

import UIAbilityContext from 'application.UIAbilityContext';
import Want from '@ohos.app.ability.Want';

export default namespace appRecovery {
    loadLibrary("appRecovery_ani");
    export enum RestartFlag {
        ALWAYS_RESTART = 0,
        RESTART_WHEN_JS_CRASH = 0x0001,
        RESTART_WHEN_APP_FREEZE = 0x0002,
        NO_RESTART = 0xFFFF
    }

    export enum SaveOccasionFlag {
        SAVE_WHEN_ERROR = 0x0001,
        SAVE_WHEN_BACKGROUND = 0x0002
    }

    export enum SaveModeFlag {
        SAVE_WITH_FILE = 0x0001,
        SAVE_WITH_SHARED_MEMORY = 0x0002
    }

    export native function enableAppRecovery(restart?: RestartFlag, saveOccasion?: SaveOccasionFlag,
        saveMode?: SaveModeFlag): void;
    export native function restartApp(): void;
    export native function setRestartWant(want: Want): void;
    export native function saveAppState(context?: UIAbilityContext): boolean;
}
