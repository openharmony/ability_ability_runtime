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

namespace AbilityConstant {
  export interface LaunchParam {
    launchReason: LaunchReason;
    launchReasonMessage?: string;
    lastExitReason: LastExitReason;
    lastExitMessage: string;
  }

  export enum LaunchReason {
    UNKNOWN = 0,
    START_ABILITY = 1,
    CALL = 2,
    CONTINUATION = 3,
    APP_RECOVERY = 4,
    SHARE = 5,
    AUTO_STARTUP = 8,
    INSIGHT_INTENT = 9,
    PREPARE_CONTINUATION = 10,
  }
  export enum LastExitReason {
    UNKNOWN = 0,
    ABILITY_NOT_RESPONDING = 1,
    NORMAL = 2,
    CPP_CRASH = 3,
    JS_ERROR = 4,
    APP_FREEZE = 5,
    PERFORMANCE_CONTROL = 6,
    RESOURCE_CONTROL = 7,
    UPGRADE = 8,
    USER_REQUEST = 9,
    SIGNAL = 10
  }
  export enum OnContinueResult {
    AGREE = 0,
    REJECT = 1,
    MISMATCH = 2
  }
  export enum MemoryLevel {
    MEMORY_LEVEL_MODERATE = 0,
    MEMORY_LEVEL_LOW = 1,
    MEMORY_LEVEL_CRITICAL = 2
  }
  export enum WindowMode {
    WINDOW_MODE_UNDEFINED = 0,
    WINDOW_MODE_FULLSCREEN = 1,
    WINDOW_MODE_SPLIT_PRIMARY = 100,
    WINDOW_MODE_SPLIT_SECONDARY = 101,
    WINDOW_MODE_FLOATING = 102
  }
  export enum OnSaveResult {
    ALL_AGREE = 0,
    CONTINUATION_REJECT = 1,
    CONTINUATION_MISMATCH = 2,
    RECOVERY_AGREE = 3,
    RECOVERY_REJECT = 4,
    ALL_REJECT
  }
  export enum StateType {
    CONTINUATION = 0,
    APP_RECOVERY = 1
  }
  export enum ContinueState {
    ACTIVE = 0,
    INACTIVE = 1
  }
  export enum CollaborateResult {
    ACCEPT = 0,
    REJECT = 1,
  }
  export enum PrepareTermination {
    TERMINATE_IMMEDIATELY = 0,
    CANCEL = 1
  }
}

class LaunchParamImpl implements AbilityConstant.LaunchParam {
  launchReason: AbilityConstant.LaunchReason = AbilityConstant.LaunchReason.UNKNOWN;
  launchReasonMessage?: string | undefined;
  lastExitReason: AbilityConstant.LastExitReason = AbilityConstant.LastExitReason.UNKNOWN;
  lastExitMessage: string = '';
}

export default AbilityConstant;
