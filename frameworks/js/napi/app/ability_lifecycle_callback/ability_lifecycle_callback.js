/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
let hilog = requireNapi('hilog');

let domainID = 0xD001320;
let TAG = 'JSENV';

class AbilityLifecycleCallback {
  constructor() {}

  onAbilityCreate(ability) {
    hilog.sLogI(domainID, TAG, 'onAbilityCreate');
  }

  onWindowStageCreate(ability, windowStage) {
    hilog.sLogI(domainID, TAG, 'onWindowStageCreate');
  }

  onWindowStageActive(ability, windowStage) {
    hilog.sLogI(domainID, TAG, 'onWindowStageActive');
  }

  onWindowStageInactive(ability, windowStage) {
    hilog.sLogI(domainID, TAG, 'onWindowStageInactive');
  }

  onWindowStageDestroy(ability, windowStage) {
    hilog.sLogI(domainID, TAG, 'onWindowStageDestroy');
  }

  onAbilityDestroy(ability) {
    hilog.sLogI(domainID, TAG, 'onAbilityDestroy');
  }

  onAbilityForeground(ability) {
    hilog.sLogI(domainID, TAG, 'onAbilityForeground');
  }

  onAbilityBackground(ability) {
    hilog.sLogI(domainID, TAG, 'onAbilityBackground');
  }

  onAbilityContinue(ability) {
    hilog.sLogI(domainID, TAG, 'onAbilityContinue');
  }

  onNewWant(ability) {
    hilog.sLogI(domainID, TAG, 'onNewWant');
  }

  onWillNewWant(ability) {
    hilog.sLogI(domainID, TAG, 'onWillNewWant');
  }

  onAbilityWillCreate(ability) {
    hilog.sLogI(domainID, TAG, 'onAbilityWillCreate');
  }

  onWindowStageWillCreate(ability, windowStage) {
    hilog.sLogI(domainID, TAG, 'onWindowStageWillCreate');
  }

  onWindowStageWillDestroy(ability, windowStage) {
    hilog.sLogI(domainID, TAG, 'onWindowStageWillDestroy');
  }

  onAbilityWillDestroy(ability) {
    hilog.sLogI(domainID, TAG, 'onAbilityWillDestroy');
  }

  onAbilityWillForeground(ability) {
    hilog.sLogI(domainID, TAG, 'onAbilityWillForeground');
  }

  onAbilityWillBackground(ability) {
    hilog.sLogI(domainID, TAG, 'onAbilityWillBackground');
  }

  onAbilityWillContinue(ability) {
    hilog.sLogI(domainID, TAG, 'onAbilityWillContinue');
  }

  onWindowStageWillRestore(ability, windowStage) {
    hilog.sLogI(domainID, TAG, 'onWindowStageWillRestore');
  }

  onWindowStageRestore(ability, windowStage) {
    hilog.sLogI(domainID, TAG, 'onWindowStageRestore');
  }

  onAbilityWillSaveState(ability) {
    hilog.sLogI(domainID, TAG, 'onAbilityWillSaveState');
  }

  onAbilitySaveState(ability) {
    hilog.sLogI(domainID, TAG, 'onAbilitySaveState');
  }
}

export default AbilityLifecycleCallback;