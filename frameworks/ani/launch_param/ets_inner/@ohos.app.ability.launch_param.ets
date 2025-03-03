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

   
// export enum LaunchReason {
//     UNKNOWN = 0,
//     START_ABILITY = 1,
//     CALL = 2,
//     CONTINUATION = 3,
//     APP_RECOVERY = 4,
//     SHARE = 5,
//     AUTO_STARTUP = 8,
//     INSIGHT_INTENT = 9,
//     PREPARE_CONTINUATION = 10,
//   }
// export enum LastExitReason {
//     UNKNOWN = 0,
//     ABILITY_NOT_RESPONDING = 1,
//     NORMAL = 2,
//     CPP_CRASH = 3,
//     JS_ERROR = 4,
//     APP_FREEZE = 5,
//     PERFORMANCE_CONTROL = 6,
//     RESOURCE_CONTROL = 7,
//     UPGRADE = 8
//   }

// export default interface LaunchParam {
//     readonly launchReason: LaunchReason;
//     readonly lastExitReason: LastExitReason;
//     readonly lastExitMessage: string;
// }

// class LaunchParamInner implements LaunchParam {
//     public launchReason: LaunchReason = LaunchReason.UNKNOWN;
//     public lastExitReason: LastExitReason = LastExitReason.UNKNOWN;
//     public lastExitMessage: string = '';
// }

// generate_static_abc("launch_param_abc") {
//     arktsconfig =
//         "${ability_runtime_path}/frameworks/ani/launch_param/launch_param.json"
//     dst_file = "$target_out_dir/launch_param.abc"
//     out_puts = [ "$target_out_dir/launch_param.abc" ]
//     is_boot_abc = "True"
//     device_dst_file = "system/framework/launch_param.abc"
//   }
