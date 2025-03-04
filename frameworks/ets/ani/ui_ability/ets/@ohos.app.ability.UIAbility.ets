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

import {AbilityConstant} from './@ohos.app.ability.AbilityConstant';
import {UIAbilityContext} from './UIAbilityContext';
import Want from './@ohos.app.ability.Want';

// class LaunchParamImpl implements AbilityConstant.LaunchParam {
//   launchReason: AbilityConstant.LaunchReason;
//   launchReasonMessage?: string|undefined;
//   lastExitReason: AbilityConstant.LastExitReason;
//   lastExitMessage: string = '';
// }

export default class UIAbility {

  context: UIAbilityContext = new UIAbilityContext();
  launchWant: Want = new Want();
  lastRequestWant: Want = new Want();

  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void{
    console.log("onCreate");
  }
  // onWindowStageCreate(): void{}

  onWindowStageDestroy(): void{
    console.log("onWindowStageDestroy");
  }
  onDestroy(): void {
    console.log("onDestroy");
  }
  onForeground(): void{
    console.log("onForeground");
  }
  onBackground(): void{
    console.log("onBackground");
  }
  onNewWant(want: Want, launchParam: AbilityConstant.LaunchParam): void{
    console.log("onDestroy");
  }
}
